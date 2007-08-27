{-# OPTIONS -keep-hc-file #-}
------------------------------------------------------------------------------
-- |
--  Module	: Network.Pcap
--  Copyright	: Bryan O'Sullivan 2007, Antiope Associates LLC 2004
--  License	: BSD-style
--  Maintainer	: bos@serpentine.com
--  Stability	: experimental
--  Portability	: non-portable
-- 
-- The 'Network.Pcap' module is a binding to all of the functions in
-- @libpcap@.  See <http://www.tcpdump.org> for more information.
-- 
-- Only a minimum of marshaling is done. To convert captured packet
-- data to a 'B.ByteString' (space efficient, and with /O(1)/ access
-- to every byte in a captured packet), use 'toBS'.
-- 
-- To convert captured packet data to a list, extract the length of
-- the captured buffer from the packet header record and use
-- 'peekArray' to convert the captured data to a list.  For
-- illustration:
--
-- >	import Network.Pcap
-- >	import Foreign.Marshal.Array (peekArray)
-- >
-- >	main = do
-- >        let printIt :: PktHdr -> Ptr Word8 -> IO ()
-- >		printIt ph bytep = do
-- >	          a <- peekArray (fromIntegral (caplen ph)) bytep 
-- >	       	  print a
-- >
-- >	    p <- openLive "em0" 100 True 10000
-- >	    s <- withForeignPtr p $ \ptr -> do
-- >	           dispatch ptr (-1) printIt
-- >	    return ()
-- 
-- Note that the 'SockAddr' exported here is not the @SockAddr@ from
-- 'Network.Socket'. The @SockAddr@ from 'Network.Socket' corresponds
-- to @struct sockaddr_in@ in BSD terminology. The 'SockAddr' record
-- here is BSD's @struct sockaddr@. See W.R.Stevens, TCP Illustrated,
-- volume 2, for further elucidation.
-- 
-- This binding should be portable across systems that can use the
-- @libpcap@ from @tcpdump.org@. It will not work with Winpcap, a
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
    , Link(..)
    , Interface(..)
    , PcapAddr(..)
    , SockAddr(..)
    , Network(..)
    , PktHdr(..)
    , Statistics(..)

    -- * Device opening
    , openOffline		-- :: String -> IO Pcap
    , openLive           -- :: String -> Int -> Bool -> Int -> IO Pcap
    , openDead                  -- :: Int    -> Int -> IO Pcap
    , openDump                 -- :: PcapHandle -> String -> IO Pdump

    -- * Filter handling
    , setFilter -- :: PcapHandle -> String -> Bool -> Word32 -> IO ()
    , compileFilter -- :: Int -> Int  -> String -> Bool -> Word32 -> IO BpfProgram

    -- * Device utilities
    , lookupDev                 -- :: IO String
    , findAllDevs		-- :: IO [Interface]
    , lookupNet                 -- :: String -> IO Network

    -- * Interface control
    -- ** Blocking mode
    , setNonBlock		-- :: PcapHandle -> Bool -> IO ()
    , getNonBlock		-- :: PcapHandle -> IO Bool

    -- ** Link layer utilities
    , datalink                  -- :: PcapHandle -> IO Link
    , setDatalink		-- :: PcapHandle -> Link -> IO ()
    , listDatalinks		-- :: PcapHandle -> IO [Link]

    -- * Packet processing
    , dispatch		-- :: PcapHandle -> Int -> Callback -> IO Int
    , loop			-- :: PcapHandle -> Int -> Callback -> IO Int
    , next			-- :: PcapHandle -> IO (PktHdr, Ptr Word8)
    , dump			-- :: Ptr PcapDumpTag -> Ptr PktHdr -> Ptr Word8 -> IO ()

    -- * Conversion
    , toBS
    , toPktHdr
    , hdrTime
    , hdrDiffTime

    -- * Miscellaneous
    , statistics		-- :: PcapHandle -> IO Statistics
    , version		-- :: PcapHandle -> IO (Int, Int)
    , isSwapped		-- :: PcapHandle -> IO Bool
    , snapshotLen		-- :: PcapHandle -> IO Int
    ) where

import qualified Data.ByteString.Base as B
import Data.Int (Int64)
import Data.Time.Clock (DiffTime, picosecondsToDiffTime)
import Data.Word ( Word8, Word32 )
import Foreign.Ptr ( Ptr )
import Foreign.ForeignPtr (ForeignPtr, withForeignPtr)
import qualified Network.Pcap.Base as P
import Network.Pcap.Base (BpfProgram, Callback, Interface(..), Link(..),
                          Network(..),
                          PcapAddr(..), PktHdr(..), SockAddr(..), Statistics,
                          compileFilter, findAllDevs, lookupDev, lookupNet,
                          toPktHdr)


-- | packet capture descriptor
newtype PcapHandle  = PcapHandle (ForeignPtr P.PcapTag)

-- | savefile descriptor
newtype DumpHandle = DumpHandle (ForeignPtr P.PcapDumpTag)

--
-- Open a device
--

-- | 'openOffline' opens a \"savefile\" for reading. The file foramt
-- is the as used for @tcpdump@. The string \"-\" is a synonym for
-- @stdin@.
--
openOffline :: String	-- ^ filename
	    -> IO PcapHandle
openOffline = fmap PcapHandle . P.openOffline

-- | 'openLive' is used to get a packet descriptor that can be used to
-- look at packets on the network. The arguments are the device name,
-- the snapshot legnth (in bytes), the promiscuity of the interface
-- ('True' == promiscuous) and a timeout in milliseconds.
-- 
-- Using \"any\" as the device name will capture packets from all
-- interfaces.  On some systems, reading from the \"any\" device is
-- incompatible with setting the interfaces into promiscuous mode. In
-- that case, only packets whose link layer addresses match those of
-- the interfaces are captured.
--
openLive :: String	-- ^ device name
	 -> Int		-- ^ snapshot length
	 -> Bool	-- ^ set to promiscuous mode?
	 -> Int		-- ^ timeout in milliseconds
	 -> IO PcapHandle
openLive name snaplen promisc timeout =
    PcapHandle `fmap` P.openLive name snaplen promisc timeout

-- | 'openDead' is used to get a packet capture descriptor without
-- opening a file or device. It is typically used to test packet
-- filter compilation by 'setFilter'. The arguments are the link type
-- and the snapshot length.
--
openDead :: Link		-- ^ datalink type
	 -> Int		-- ^ snapshot length
	 -> IO PcapHandle	-- ^ packet capture descriptor
openDead link snaplen = PcapHandle `fmap` P.openDead link snaplen

{-# INLINE withPcap #-}
withPcap :: PcapHandle -> (Ptr P.PcapTag -> IO a) -> IO a
withPcap (PcapHandle hdl) f = withForeignPtr hdl f

{-# INLINE withDump #-}
withDump :: DumpHandle -> (Ptr P.PcapDumpTag -> IO a) -> IO a
withDump (DumpHandle hdl) f = withForeignPtr hdl f

--
-- Open a dump device
--

-- | 'openDump' opens a \"save file\" for writing. This save file is
-- written to by the dump function. The arguments are a raw packet
-- capture descriptor and the filename, with \"-\" as a synonym for
-- @stdout@.
openDump :: PcapHandle	-- ^ packet capture descriptor
	 -> String	-- ^ savefile name
	 -> IO DumpHandle	-- ^ davefile descriptor
openDump pch name = withPcap pch $ \hdl ->
    DumpHandle `fmap` P.openDump hdl name

--
-- Set the filter
--

-- | Set a filter on the specified packet capture descriptor. Valid
-- filter strings are those accepted by @tcpdump@.
setFilter :: PcapHandle	-- ^ packet capture descriptor
	  -> String	-- ^ filter string
	  -> Bool		-- ^ optimize?
	  -> Word32	-- ^ IPv4 network mask
	  -> IO ()
setFilter pch filt opt mask = withPcap pch $ \hdl ->
    P.setFilter hdl filt opt mask


--
-- Set or read the device mode (blocking/nonblocking)
--

-- | Set a packet capture descriptor into non-blocking mode, if the
-- second argument is True, otherwise put it in blocking mode. Note
-- that the packet capture descriptor must have been obtaine from
-- 'openLive'.
--
setNonBlock :: PcapHandle -> Bool -> IO ()
setNonBlock pch block = withPcap pch $ \hdl -> P.setNonBlock hdl block

-- | Return the blocking status of the packet capture
-- descriptor. 'True' indicates that the descriptor is
-- non-blocking. Descriptors referring to savefiles opened by
-- 'openDump' always return 'False'.
getNonBlock :: PcapHandle -> IO Bool
getNonBlock pch = withPcap pch P.getNonBlock

{-# INLINE hdrTime #-}
-- | Get the timestamp of a packet as a single quantity, in microseconds.
hdrTime :: PktHdr -> Int64
hdrTime pkt = fromIntegral (hdrSeconds pkt) * 1000000 +
              fromIntegral (hdrUseconds pkt)

-- | Get the timestamp of a packet as a 'DiffTime'.
hdrDiffTime :: PktHdr -> DiffTime
hdrDiffTime pkt = picosecondsToDiffTime (fromIntegral (hdrTime pkt) * 1000000)

--
-- Reading packets
--

-- | Collect and process packets. The arguments are the packet capture
-- descriptor, the count and a callback function.
--
-- The count is the maximum number of packets to process before
-- returning.  A count of -1 means process all of the packets received
-- in one buffer (if a live capture) or all of the packets in a
-- savefile (if offline).
--
-- The callback function is passed two arguments, a packet header
-- record and a pointer to the packet data (@Ptr Word8@). THe header
-- record contains the number of bytes captured, whcih can be used to
-- marshal the data into a list or array.
--
dispatch :: PcapHandle	-- ^ packet capture descriptor
	 -> Int		-- ^ number of packets to process
	 -> Callback	-- ^ packet processing function
	 -> IO Int	-- ^ number of packets read
dispatch pch count f = withPcap pch $ \hdl -> P.dispatch hdl count f

-- | Similar to 'dispatch', but loop until the number of packets
-- specified by the second argument are read. A negative value loops
-- forever.
-- 
-- This function does not return when a live read tiemout occurs. Use
-- 'dispatch' instead if you wnat to specify a timeout.
loop :: PcapHandle	-- ^ packet cpature descriptor
     -> Int		-- ^ number of packet to read
     -> Callback	-- ^ packet processing function
     -> IO Int	-- ^ number of packets read
loop pch count f = withPcap pch $ \hdl -> P.loop hdl count f


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
next :: PcapHandle			-- ^ packet capture descriptor
     -> IO (PktHdr, Ptr Word8)	-- ^ packet header and data of the next packet
next pch = withPcap pch P.next

-- | Write the packet data given by the second and third arguments to
-- a savefile opened by 'openDead'. 'dump' is designed so it can be
-- easily used as a default callback function by 'dispatch' or 'loop'.
dump :: DumpHandle	-- ^ savefile descriptor
     -> Ptr PktHdr		-- ^ packet header record
     -> Ptr Word8		-- ^ packet data
     -> IO ()
dump dh hdr pkt = withDump dh $ \hdl -> P.dump hdl hdr pkt

--
-- Datalink manipulation
--

-- | Returns the datalink type associated with the given pcap
-- descriptor.
--
datalink :: PcapHandle -> IO Link
datalink pch = withPcap pch P.datalink


-- | Sets the datalink type for a given pcap descriptor.
--
setDatalink :: PcapHandle -> Link -> IO ()
setDatalink pch link = withPcap pch $ \hdl -> P.setDatalink hdl link

-- | List all the datalink types supported by a pcap
-- descriptor. Entries from the resulting list are valid arguments to
-- 'setDatalink'.
listDatalinks :: PcapHandle -> IO [Link]
listDatalinks pch = withPcap pch P.listDatalinks
		
-- | Returns the number of packets received, the number of packets
-- dropped by the packet filter and the number of packets dropped by
-- the interface (before processing by the packet filter).
--
statistics :: PcapHandle -> IO Statistics
statistics pch = withPcap pch P.statistics

--
-- Version information
--

-- | Version of the library.  The returned pair consists of the major
-- and minor version numbers.
version :: PcapHandle -> IO (Int, Int)
version pch = withPcap pch P.version

-- | 'isSwapped' returns 'True' if the current save file uses a
-- different byte order than the one native to the system.
isSwapped :: PcapHandle -> IO Bool
isSwapped pch = withPcap pch P.isSwapped


-- | The snapshot length that was used in the call to 'openLive'.
snapshotLen :: PcapHandle -> IO Int
snapshotLen pch = withPcap pch P.snapshotLen
