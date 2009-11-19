------------------------------------------------------------------------------
-- |
--  Module      : Network.Pcap
--  Copyright   : Bryan O'Sullivan 2007, Antiope Associates LLC 2004
--  License     : BSD-style
--  Maintainer  : bos@serpentine.com
--  Stability   : experimental
--  Portability : non-portable
--
-- The 'Network.Pcap' module is a high(ish) level binding to all of
-- the functions in @libpcap@.  See <http://www.tcpdump.org> for more
-- information.
--
-- This module is built on the lower-level 'Network.Pcap.Base' module,
-- which is slightly more efficient.  Don\'t use 'Network.Pcap.Base'
-- unless profiling data indicates that you need to.
--
-- Only a minimum of marshaling is done on received packets.  To
-- convert captured packet data to a 'B.ByteString' (space efficient,
-- and with /O(1)/ access to every byte in a captured packet), use
-- 'toBS'.
--
-- Note that the 'SockAddr' exported here is not the @SockAddr@ from
-- 'Network.Socket'. The @SockAddr@ from 'Network.Socket' corresponds
-- to @struct sockaddr_in@ in BSD terminology. The 'SockAddr' record
-- here is BSD's @struct sockaddr@. See W.R.Stevens, TCP Illustrated,
-- volume 2, for further elucidation.
--
-- This binding should be portable across systems that can use the
-- @libpcap@ from @tcpdump.org@. It does not yet work with Winpcap, a
-- similar library for Windows, although adapting it should not prove
-- difficult.
--
------------------------------------------------------------------------------

module Network.Pcap
    (
      -- * Types
      PcapHandle
    , DumpHandle
    , BpfProgram
    , Callback
    , CallbackBS
    , Direction(..)
    , Link(..)
    , Interface(..)
    , PcapAddr(..)
    , SockAddr(..)
    , Network(..)
    , PktHdr(..)
    , Statistics(..)

    -- * Device opening
    , openOffline               -- :: FilePath -> IO Pcap
    , openLive                  -- :: String -> Int -> Bool -> Int -> IO Pcap
    , openDead                  -- :: Int -> Int -> IO Pcap
    , openDump                  -- :: PcapHandle -> FilePath -> IO Pdump

    -- * Filter handling
    , setFilter                 -- :: PcapHandle -> String -> Bool -> Word32 -> IO ()
    , compileFilter             -- :: Int -> Int -> String -> Bool -> Word32 -> IO BpfProgram

    -- * Device utilities
    , lookupDev                 -- :: IO String
    , findAllDevs               -- :: IO [Interface]
    , lookupNet                 -- :: String -> IO Network

    -- * Interface control

    , setNonBlock               -- :: PcapHandle -> Bool -> IO ()
    , getNonBlock               -- :: PcapHandle -> IO Bool
    , setDirection

    -- * Link layer utilities
    , datalink                  -- :: PcapHandle -> IO Link
    , setDatalink               -- :: PcapHandle -> Link -> IO ()
    , listDatalinks             -- :: PcapHandle -> IO [Link]

    -- * Packet processing
    , dispatch                  -- :: PcapHandle -> Int -> Callback -> IO Int
    , loop                      -- :: PcapHandle -> Int -> Callback -> IO Int
    , next                      -- :: PcapHandle -> IO (PktHdr, Ptr Word8)
    , dump                      -- :: Ptr PcapDumpTag -> Ptr PktHdr -> Ptr Word8 -> IO ()

    -- ** 'B.ByteString' variants
    , dispatchBS                -- :: PcapHandle -> Int -> CallbackBS -> IO Int
    , loopBS                    -- :: PcapHandle -> Int -> CallbackBS -> IO Int
    , nextBS                    -- :: PcapHandle -> IO (PktHdr, B.ByteStringa)
    , dumpBS                    -- :: Ptr PcapDumpTag -> Ptr PktHdr -> B.ByteString -> IO ()

    -- * Sending packets
    , sendPacket
    , sendPacketBS

    -- * Conversion
    , toBS
    , hdrTime
    , hdrDiffTime

    -- * Miscellaneous
    , statistics                -- :: PcapHandle -> IO Statistics
    , version                   -- :: PcapHandle -> IO (Int, Int)
    , isSwapped                 -- :: PcapHandle -> IO Bool
    , snapshotLen               -- :: PcapHandle -> IO Int
    ) where

#ifdef BYTESTRING_IN_BASE
import qualified Data.ByteString.Base as B
import qualified Data.ByteString.Base as BU
#else
import qualified Data.ByteString.Internal as B
import qualified Data.ByteString.Unsafe as BU
#endif
import Data.Int (Int64)
import Data.Time.Clock (DiffTime, picosecondsToDiffTime)
import Data.Word (Word8, Word32)
import Foreign.Ptr (Ptr, castPtr)
import Foreign.ForeignPtr (ForeignPtr, withForeignPtr)
import qualified Network.Pcap.Base as P
import Network.Pcap.Base (BpfProgram, Callback, Interface(..), Link(..),
                          Network(..), Direction(..),
                          PcapAddr(..), PktHdr(..), SockAddr(..), Statistics,
                          compileFilter, findAllDevs, lookupDev, lookupNet)

-- | Packet capture handle.
newtype PcapHandle = PcapHandle (ForeignPtr P.PcapTag)

-- | Dump file handle.
newtype DumpHandle = DumpHandle (ForeignPtr P.PcapDumpTag)

-- | Callback using 'B.ByteString' for packet body.
type CallbackBS = PktHdr -> B.ByteString -> IO ()

--
-- Open a device
--

-- | 'openOffline' opens a dump file for reading. The file format is
-- the same as used by @tcpdump@ and Wireshark. The string @\"-\"@ is
-- a synonym for @stdin@.
--
openOffline :: FilePath -- ^ name of dump file to read
            -> IO PcapHandle
openOffline = fmap PcapHandle . P.openOffline

-- | 'openLive' is used to get a 'PcapHandle' that can be used to look
-- at packets on the network. The arguments are the device name, the
-- snapshot length (in bytes), the promiscuity of the interface
-- ('True' == promiscuous) and a timeout in microseconds.
--
-- The timeout allows the packet filter to delay while accumulating
-- multiple packets, which is more efficient than reading packets one
-- by one.  A timeout of zero will wait indefinitely for \"enough\"
-- packets to arrive.
--
-- Using @\"any\"@ as the device name will capture packets from all
-- interfaces.  On some systems, reading from the @\"any\"@ device is
-- incompatible with setting the interfaces into promiscuous mode. In
-- that case, only packets whose link layer addresses match those of
-- the interfaces are captured.
--
openLive :: String              -- ^ device name
         -> Int                 -- ^ snapshot length
         -> Bool                -- ^ set interface to promiscuous mode?
         -> Int64               -- ^ timeout in microseconds
         -> IO PcapHandle
openLive name snaplen promisc timeout =
    let timeout' | timeout <= 0 = 0
                 | otherwise = fromIntegral (timeout `div` 1000)
    in PcapHandle `fmap` P.openLive name snaplen promisc timeout'

-- | 'openDead' is used to get a 'PcapHandle' without opening a file
-- or device. It is typically used to test packet filter compilation
-- by 'setFilter'. The arguments are the link type and the snapshot
-- length.
--
openDead :: Link                -- ^ datalink type
         -> Int                 -- ^ snapshot length
         -> IO PcapHandle
openDead link snaplen = PcapHandle `fmap` P.openDead link snaplen

{-# INLINE withPcap #-}
withPcap :: PcapHandle -> (Ptr P.PcapTag -> IO a) -> IO a
withPcap (PcapHandle hdl) = withForeignPtr hdl

{-# INLINE withDump #-}
withDump :: DumpHandle -> (Ptr P.PcapDumpTag -> IO a) -> IO a
withDump (DumpHandle hdl) = withForeignPtr hdl

--
-- Open a dump device
--

-- | 'openDump' opens a dump file for writing. This dump file is
-- written to by the 'dump' function.
openDump :: PcapHandle          -- ^ packet capture handle
         -> FilePath            -- ^ name of dump file to write to
         -> IO DumpHandle
openDump pch name = withPcap pch $ \hdl ->
    DumpHandle `fmap` P.openDump hdl name

--
-- Set the filter
--

-- | Set a filter on the specified packet capture handle. Valid filter
-- strings are those accepted by @tcpdump@.
setFilter :: PcapHandle         -- ^ handle on which to set filter
          -> String             -- ^ filter string
          -> Bool               -- ^ optimize?
          -> Word32             -- ^ IPv4 network mask
          -> IO ()
setFilter pch filt opt mask = withPcap pch $ \hdl ->
    P.setFilter hdl filt opt mask

--
-- Set or read the device mode (blocking/nonblocking)
--

-- | Set the given 'PcapHandle' into non-blocking mode if the second
-- argument is 'True', otherwise put it in blocking mode. Note that
-- the 'PcapHandle' must have been obtained from 'openLive'.
--
setNonBlock :: PcapHandle       -- ^ must have been obtained from 'openLive'
            -> Bool             -- ^ set\/unset blocking mode
            -> IO ()
setNonBlock pch block = withPcap pch $ \hdl -> P.setNonBlock hdl block

-- | Return the blocking status of the 'PcapHandle'. 'True' indicates
-- that the handle is non-blocking. Handles referring to dump files
-- opened by 'openDump' always return 'False'.
getNonBlock :: PcapHandle -> IO Bool
getNonBlock pch = withPcap pch P.getNonBlock

-- | Specify the direction in which packets are to be captured.
-- Complete functionality is not necessarily available on all
-- platforms.
setDirection :: PcapHandle -> Direction -> IO ()
setDirection pch dir = withPcap pch $ \hdl -> P.setDirection hdl dir

{-# INLINE hdrTime #-}
-- | Get the timestamp of a packet as a single quantity, in
-- microseconds.
hdrTime :: PktHdr -> Int64
hdrTime pkt = fromIntegral (hdrSeconds pkt) * 1000000 +
              fromIntegral (hdrUseconds pkt)

-- | Get the timestamp of a packet as a 'DiffTime'.
hdrDiffTime :: PktHdr -> DiffTime
hdrDiffTime pkt = picosecondsToDiffTime (fromIntegral (hdrTime pkt) * 1000000)

--
-- Reading packets
--

-- | Wrap a callback that expects a 'B.ByteString' so that it is
-- usable as a regular 'Callback'.
wrapBS :: CallbackBS -> Callback
wrapBS f hdr ptr = do
  let len = hdrCaptureLength hdr
  bs <- B.create (fromIntegral len) $ \p -> B.memcpy p ptr (fromIntegral len)
  f hdr bs

-- | Collect and process packets.
--
-- The count is the maximum number of packets to process before
-- returning.  A count of -1 means process all of the packets received
-- in one buffer (if a live capture) or all of the packets in a dump
-- file (if offline).
--
-- The callback function is passed two arguments, a packet header
-- record and a pointer to the packet data (@Ptr Word8@). THe header
-- record contains the number of bytes captured, which can be used to
-- marshal the data into a list, array, or 'B.ByteString' (using
-- 'toBS').
--
dispatch :: PcapHandle
         -> Int                 -- ^ number of packets to process
         -> Callback            -- ^ packet processing function
         -> IO Int              -- ^ number of packets read
dispatch pch count f = withPcap pch $ \hdl -> P.dispatch hdl count f

-- | Variant of 'dispatch' for use with 'B.ByteString'.
dispatchBS :: PcapHandle
           -> Int               -- ^ number of packets to process
           -> CallbackBS        -- ^ packet processing function
           -> IO Int            -- ^ number of packets read
dispatchBS pch count f = withPcap pch $ \hdl -> P.dispatch hdl count (wrapBS f)

-- | Similar to 'dispatch', but loop until the number of packets
-- specified by the second argument are read. A negative value loops
-- forever.
--
-- This function does not return when a live read timeout occurs. Use
-- 'dispatch' instead if you want to specify a timeout.
loop :: PcapHandle
     -> Int                     -- ^ number of packets to read (-1 == loop forever)
     -> Callback                -- ^ packet processing function
     -> IO Int                  -- ^ number of packets read
loop pch count f = withPcap pch $ \hdl -> P.loop hdl count f

-- | Variant of 'loop' for use with 'B.ByteString'.
loopBS :: PcapHandle
       -> Int                   -- ^ number of packets to read (-1 == loop forever)
       -> CallbackBS            -- ^ packet processing function
       -> IO Int                -- ^ number of packets read
loopBS pch count f = withPcap pch $ \hdl -> P.loop hdl count (wrapBS f)

-- | Send a raw packet through the network interface.
sendPacket :: PcapHandle
           -> Ptr Word8         -- ^ packet data (including link-level header)
           -> Int               -- ^ packet size
           -> IO ()
sendPacket pch buf size = withPcap pch $ \hdl -> P.sendPacket hdl buf size

-- | Variant of 'sendPacket' for use with 'B.ByteString'.
sendPacketBS :: PcapHandle
             -> B.ByteString    -- ^ packet data (including link-level header)
             -> IO ()
sendPacketBS pch s = BU.unsafeUseAsCStringLen s $ \(buf, len) ->
    sendPacket pch (castPtr buf) len

-- | Represent a captured packet as a 'B.ByteString'.  Suitable for
-- use as is with the result of 'next', or use @'curry' 'toBS'@ inside
-- a 'Callback' with 'dispatch'.
toBS :: (PktHdr, Ptr Word8) -> IO (PktHdr, B.ByteString)
toBS (hdr, ptr) = do
    let len = hdrCaptureLength hdr
    s <- B.create (fromIntegral len) $ \p -> B.memcpy p ptr (fromIntegral len)
    return (hdr, s)

-- | Read the next packet (equivalent to calling 'dispatch' with a
-- count of 1).
next :: PcapHandle -> IO (PktHdr, Ptr Word8)
next pch = withPcap pch P.next

nextBS :: PcapHandle -> IO (PktHdr, B.ByteString)
nextBS pch = withPcap pch P.next >>= toBS

-- | Write the packet data given by the second and third arguments to
-- a dump file opened by 'openDead'. 'dump' is designed so it can be
-- easily used as a default callback function by 'dispatch' or 'loop'.
dump :: DumpHandle
     -> Ptr PktHdr              -- ^ packet header record
     -> Ptr Word8               -- ^ packet data
     -> IO ()
dump dh hdr pkt = withDump dh $ \hdl -> P.dump hdl hdr pkt

dumpBS :: DumpHandle
       -> Ptr PktHdr            -- ^ packet header record
       -> B.ByteString          -- ^ packet data
       -> IO ()
dumpBS dh hdr s =
    withDump dh $ \hdl ->
        BU.unsafeUseAsCString s $ P.dump hdl hdr . castPtr

--
-- Datalink manipulation
--

-- | Returns the datalink type associated with the given handle.
datalink :: PcapHandle -> IO Link
datalink pch = withPcap pch P.datalink

-- | Sets the datalink type for the given handle.
setDatalink :: PcapHandle -> Link -> IO ()
setDatalink pch link = withPcap pch $ \hdl -> P.setDatalink hdl link

-- | List all the datalink types supported by the given
-- handle. Entries from the resulting list are valid arguments to
-- 'setDatalink'.
listDatalinks :: PcapHandle -> IO [Link]
listDatalinks pch = withPcap pch P.listDatalinks

-- | Returns the number of packets received, the number of packets
-- dropped by the packet filter and the number of packets dropped by
-- the interface (before processing by the packet filter).
statistics :: PcapHandle -> IO Statistics
statistics pch = withPcap pch P.statistics

-- | Version of the library.  The returned pair consists of the major
-- and minor version numbers.
version :: PcapHandle -> IO (Int, Int)
version pch = withPcap pch P.version

-- | 'isSwapped' returns 'True' if the current dump file uses a
-- different byte order than the one native to the system.
isSwapped :: PcapHandle -> IO Bool
isSwapped pch = withPcap pch P.isSwapped

-- | The snapshot length that was used in the call to 'openLive'.
snapshotLen :: PcapHandle -> IO Int
snapshotLen pch = withPcap pch P.snapshotLen
