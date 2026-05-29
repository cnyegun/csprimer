{-# LANGUAGE BangPatterns #-}

-- This program reads a classic PCAP file and prints the same packet summary as
-- the C version. The main trick is that binary files are just bytes, so most of
-- the code below is carefully naming "where in the bytes" each field lives.

import Data.Bits ((.&.), (.|.), shiftL, shiftR)
import qualified Data.ByteString as BS
import Data.ByteString.Builder (Builder, hPutBuilder, intDec, string7, word16Dec, word32Dec)
import qualified Data.ByteString.Unsafe as BSU
import Data.Time.Clock.POSIX (posixSecondsToUTCTime)
import Data.Time.Format (defaultTimeLocale, formatTime)
import Data.Time.LocalTime (utcToLocalZonedTime)
import Data.Word (Word8, Word16, Word32)
import Numeric (showHex)
import System.IO (Handle, stdout)
import Text.Printf (printf)

-- I use these aliases so type signatures read more like English.
type Offset = Int
type ByteCount = Int

-- The capture has many packets with the same timestamp second. Caching just the
-- previous timestamp keeps the code simple and avoids most repeated formatting.
type TimestampCache = Maybe (Word32, String)

-- A classic PCAP file starts with one 24-byte global header.
pcapGlobalHeaderSize :: ByteCount
pcapGlobalHeaderSize = 24

-- Every packet then has a 16-byte per-packet header before the packet bytes.
pcapPacketHeaderSize :: ByteCount
pcapPacketHeaderSize = 16

-- Inside the per-packet header, byte 8 starts the captured packet length field.
capturedLengthOffset :: Offset
capturedLengthOffset = 8

-- This file uses a small 4-byte Linux cooked header before the IPv4 header.
linuxCookedHeaderSize :: ByteCount
linuxCookedHeaderSize = 4

-- The first IPv4 byte stores two 4-bit values: version and IHL.
ipv4VersionAndIhlOffset :: Offset
ipv4VersionAndIhlOffset = linuxCookedHeaderSize

-- IPv4 total length lives 2 bytes after the start of the IPv4 header.
ipv4TotalLengthOffset :: Offset
ipv4TotalLengthOffset = linuxCookedHeaderSize + 2

-- IPv4 protocol lives 9 bytes after the start of the IPv4 header.
ipv4ProtocolOffset :: Offset
ipv4ProtocolOffset = linuxCookedHeaderSize + 9

-- TCP flags live 13 bytes after the start of the TCP header.
tcpFlagsOffsetInTcpHeader :: Offset
tcpFlagsOffsetInTcpHeader = 13

-- Writing output in chunks avoids keeping the whole 600k-line output in memory.
packetsPerOutputChunk :: Int
packetsPerOutputChunk = 2048

-- This is the one intentionally sharp tool in the file: an unchecked byte read.
-- The packet loop checks bounds first, so we do not pay for the same checks over
-- and over while reading individual fields.
byteAt :: BS.ByteString -> Offset -> Word8
byteAt = BSU.unsafeIndex
{-# INLINE byteAt #-}

-- Read a 16-bit little-endian number: lowest byte first, highest byte second.
word16LEAt :: BS.ByteString -> Offset -> Word16
word16LEAt bytes offset =
  let !b0 = fromIntegral (byteAt bytes offset) :: Word16 -- Low byte.
      !b1 = fromIntegral (byteAt bytes (offset + 1)) :: Word16 -- High byte.
   in b0 .|. (b1 `shiftL` 8) -- Move the high byte into place and combine.
{-# INLINE word16LEAt #-}

-- Read a 16-bit big-endian number: highest byte first, lowest byte second.
word16BEAt :: BS.ByteString -> Offset -> Word16
word16BEAt bytes offset =
  let !b0 = fromIntegral (byteAt bytes offset) :: Word16 -- High byte.
      !b1 = fromIntegral (byteAt bytes (offset + 1)) :: Word16 -- Low byte.
   in (b0 `shiftL` 8) .|. b1 -- Shift the high byte left, then attach low byte.
{-# INLINE word16BEAt #-}

-- Read a 32-bit little-endian number. PCAP headers in this file use this order.
word32LEAt :: BS.ByteString -> Offset -> Word32
word32LEAt bytes offset =
  let !b0 = fromIntegral (byteAt bytes offset) :: Word32 -- Byte 0 contributes bits 0..7.
      !b1 = fromIntegral (byteAt bytes (offset + 1)) :: Word32 -- Byte 1 contributes bits 8..15.
      !b2 = fromIntegral (byteAt bytes (offset + 2)) :: Word32 -- Byte 2 contributes bits 16..23.
      !b3 = fromIntegral (byteAt bytes (offset + 3)) :: Word32 -- Byte 3 contributes bits 24..31.
   in b0
        .|. (b1 `shiftL` 8)
        .|. (b2 `shiftL` 16)
        .|. (b3 `shiftL` 24)
{-# INLINE word32LEAt #-}

-- Check whether a packet has enough bytes for a field at a relative offset.
hasBytes :: ByteCount -> Offset -> ByteCount -> Bool
hasBytes availableBytes relativeOffset neededBytes = relativeOffset + neededBytes <= availableBytes
{-# INLINE hasBytes #-}

-- Check whether the whole PCAP has enough bytes starting at an absolute offset.
hasBytesAt :: ByteCount -> Offset -> ByteCount -> Bool
hasBytesAt totalBytes offset neededBytes = offset + neededBytes <= totalBytes
{-# INLINE hasBytesAt #-}

-- Add leading characters when a hex string is shorter than the width we want.
padLeft :: Int -> Char -> String -> String
padLeft width char string = replicate (width - length string) char ++ string

-- Print the PCAP magic number like the C program: 0xa1b2c3d4.
word32Hex :: Word32 -> String
word32Hex word = "0x" ++ padLeft 8 '0' (showHex word "")

-- Convert the Unix timestamp from the packet header into local human time.
formatTimestamp :: Word32 -> IO String
formatTimestamp timestamp = do
  localTime <- utcToLocalZonedTime utcTime -- Match C's localtime behavior.
  pure $ formatTime defaultTimeLocale "%Y-%m-%d %H:%M:%S" localTime
  where
    utcTime = posixSecondsToUTCTime (fromIntegral timestamp)

-- Reuse the previous formatted timestamp if the next packet has the same time.
cachedTimestamp :: TimestampCache -> Word32 -> IO (String, TimestampCache)
cachedTimestamp cache timestamp =
  case cache of
    -- Fast path: most adjacent packets in this file share the same second.
    Just (cachedTimestampValue, formatted) | cachedTimestampValue == timestamp -> pure (formatted, cache)
    -- Slow path: only format when the second changes.
    _ -> do
      formatted <- formatTimestamp timestamp
      pure (formatted, Just (timestamp, formatted))

-- Build the two lines that come from the 24-byte PCAP global header.
buildGlobalHeader :: BS.ByteString -> Maybe Builder
buildGlobalHeader pcap
  -- If the file is too short, do not try to read fields that cannot exist.
  | BS.length pcap < pcapGlobalHeaderSize = Nothing
  | otherwise =
      let !magicNumber = word32LEAt pcap 0 -- Bytes 0..3 identify the PCAP format.
          !majorVersion = word16LEAt pcap 4 -- Bytes 4..5 are the major version.
          !minorVersion = word16LEAt pcap 6 -- Bytes 6..7 are the minor version.
       in Just $
            string7 "Magic number: "
              <> string7 (word32Hex magicNumber)
              <> string7 "\nVersion: "
              <> word16Dec majorVersion
              <> string7 "."
              <> word16Dec minorVersion
              <> string7 "\n"

-- Print the Linux cooked protocol line when the packet says it contains IPv4.
protocolLine :: BS.ByteString -> Offset -> ByteCount -> Builder
protocolLine pcap packetOffset packetLength
  | hasBytes packetLength 0 linuxCookedHeaderSize && word32LEAt pcap packetOffset == 2 = string7 "Protocol: IPv4\n"
  | otherwise = mempty

-- Convert the TCP flags byte into the two counters this program cares about.
tcpFlagCounts :: Maybe Word8 -> (Int, Int)
tcpFlagCounts maybeFlags =
  case maybeFlags of
    Just 0x02 -> (0, 1) -- SYN packet.
    Just 0x12 -> (1, 0) -- SYN + ACK packet.
    _ -> (0, 0) -- Other TCP flags do not affect the final ratio.

-- Find the TCP flags byte. IHL tells us how long the IPv4 header is, so the TCP
-- header starts after the Linux cooked header and the variable-size IPv4 header.
readTcpFlags :: BS.ByteString -> Offset -> ByteCount -> Word8 -> Maybe Word8
readTcpFlags pcap packetOffset packetLength ihl =
  if tcpFlagsOffset < packetOffset + packetLength
    then Just (byteAt pcap tcpFlagsOffset)
    else Nothing
  where
    ipv4HeaderOffset = packetOffset + linuxCookedHeaderSize
    tcpHeaderOffset = ipv4HeaderOffset + 4 * fromIntegral ihl
    tcpFlagsOffset = tcpHeaderOffset + tcpFlagsOffsetInTcpHeader

-- Build all printed lines that come from the packet body, and return how this
-- packet affects the ACK/SYN counters.
buildPacketDetails :: BS.ByteString -> Offset -> ByteCount -> (Builder, Int, Int)
buildPacketDetails pcap packetOffset packetLength
  -- Without the version/IHL byte, there is no useful IPv4 detail to print.
  | not (hasBytes packetLength ipv4VersionAndIhlOffset 1) = (mempty, 0, 0)
  | otherwise =
      let !versionAndIhl = byteAt pcap (packetOffset + ipv4VersionAndIhlOffset)
          !ipv4Version = versionAndIhl `shiftR` 4 -- Top 4 bits: IPv4 version.
          !ihl = versionAndIhl .&. 0x0f -- Bottom 4 bits: IPv4 header length.

          !totalLengthLine =
            if hasBytes packetLength ipv4TotalLengthOffset 2
              then string7 "total length: " <> word16Dec (word16BEAt pcap (packetOffset + ipv4TotalLengthOffset)) <> string7 "\n"
              else mempty

          !ipv4ProtocolLine =
            if hasBytes packetLength ipv4ProtocolOffset 1
              then string7 "ipv4 protocol: " <> intDec (fromIntegral (byteAt pcap (packetOffset + ipv4ProtocolOffset)) :: Int) <> string7 "\n"
              else mempty

          (!ackCount, !synCount) = tcpFlagCounts (readTcpFlags pcap packetOffset packetLength ihl)

          !packetText =
            protocolLine pcap packetOffset packetLength
              <> string7 "IPv4 version: "
              <> intDec (fromIntegral ipv4Version :: Int)
              <> string7 "\nIHL: "
              <> intDec (fromIntegral ihl :: Int)
              <> string7 "\n"
              <> totalLengthLine
              <> ipv4ProtocolLine
       in (packetText, ackCount, synCount)

-- Build the common lines printed before each packet's decoded body fields.
buildPacketHeaderLines :: String -> Word32 -> Builder
buildPacketHeaderLines formattedTimestamp capturedLength =
  string7 "Timestamp: "
    <> string7 formattedTimestamp
    <> string7 "\nLength: "
    <> word32Dec capturedLength
    <> string7 " bytes\n"

-- Walk through all packets. The loop carries the current byte offset, counters,
-- timestamp cache, and a chunk of output waiting to be flushed.
writePackets :: Handle -> BS.ByteString -> IO (Int, Int, Int)
writePackets handle pcap = loop Nothing pcapGlobalHeaderSize 0 0 0 0 mempty
  where
    !pcapLength = BS.length pcap -- Cache file length once; it never changes.

    flush :: Builder -> IO ()
    flush !output = hPutBuilder handle output

    loop !cache !packetHeaderOffset !totalPackets !totalAck !totalSyn !packetsInChunk !output
      -- Stop cleanly when there are not enough bytes for another packet header.
      | not (hasBytesAt pcapLength packetHeaderOffset pcapPacketHeaderSize) = do
          flush output
          pure (totalPackets, totalAck, totalSyn)
      | otherwise = do
          let !timestamp = word32LEAt pcap packetHeaderOffset
              !capturedLength = word32LEAt pcap (packetHeaderOffset + capturedLengthOffset)
              !packetLength = fromIntegral capturedLength :: ByteCount
              !packetOffset = packetHeaderOffset + pcapPacketHeaderSize

          -- Stop if the packet header claims more packet bytes than the file has.
          if not (hasBytesAt pcapLength packetOffset packetLength)
            then do
              flush output
              pure (totalPackets, totalAck, totalSyn)
            else do
              (!formattedTimestamp, !cache') <- cachedTimestamp cache timestamp
              let (!packetDetails, !ackCount, !synCount) = buildPacketDetails pcap packetOffset packetLength
                  !output' = output <> buildPacketHeaderLines formattedTimestamp capturedLength <> packetDetails
                  !packetHeaderOffset' = packetOffset + packetLength -- Jump to the next packet header.
                  !totalPackets' = totalPackets + 1
                  !totalAck' = totalAck + ackCount
                  !totalSyn' = totalSyn + synCount
                  !packetsInChunk' = packetsInChunk + 1

              -- Flush every few thousand packets to keep memory use steady.
              if packetsInChunk' >= packetsPerOutputChunk
                then do
                  flush output'
                  loop cache' packetHeaderOffset' totalPackets' totalAck' totalSyn' 0 mempty
                else
                  loop cache' packetHeaderOffset' totalPackets' totalAck' totalSyn' packetsInChunk' output'

-- Print the final counters and ratio line.
buildSummary :: Int -> Int -> Int -> Builder
buildSummary totalPackets totalAck totalSyn =
  string7 "Total package: "
    <> intDec totalPackets
    <> string7 "\n"
    <> string7 ratioLine
  where
    ratioLine :: String
    ratioLine =
      if totalSyn == 0
        then "ACK/SYN = 0.00 %\n"
        else printf "ACK/SYN = %.2f %%\n" (fromIntegral totalAck / fromIntegral totalSyn * 100 :: Double)

main :: IO ()
main = do
  pcap <- BS.readFile "synflood.pcap" -- One read keeps parsing simple and fast.

  case buildGlobalHeader pcap of
    Nothing -> putStrLn "Could not read PCAP global header"
    Just header -> do
      hPutBuilder stdout header
      (totalPackets, totalAck, totalSyn) <- writePackets stdout pcap
      hPutBuilder stdout $ buildSummary totalPackets totalAck totalSyn
