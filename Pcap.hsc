------------------------------------------------------------------------------
-- |
--  Module	: Pcap
--  Copyright	: (c) Antiope Associates LLC 2004
--  License	: BSD-style (see the file libraries/network/license)
--
--  Maintainer	: 
--  Stability	: experimental
--  Portability	: non-portable
--
--  The "Pcap" modules is a binding to all of the functions in
--  libpcap (See <http://www.tcpdump.org> for more information.)
--
--  Only a minimum of mashalling is done; for light duty applications,
--  the user can extract the length of the captured buffer
--  from the packet header record and use 'peekArray' to convert the
--  captured data to a list. For illustration:
--
-- >	import Pcap
-- >	import Foreign
-- >
-- >	main = do
-- >		let
-- >			printIt :: PktHdr -> Ptr Word8 -> IO ()
-- >			printIt ph bytep = do
-- >	        		a <- peekArray (fromIntegral (caplen ph)) bytep 
-- >	       			print a
-- >
-- >	        p <- openLive "em0" 100 True 10000
-- >	        s <- withForeignPtr p $ \ptr -> do
-- >	                dispatch ptr (-1) printIt
-- >	        return ()
-- >
--
--  Users requiring higher perfomance (such as O(1) access to any byte
--  in a packet) should roll their own marshalling functions.
--
--  Note that the SockAddr exported here is not the SockAddr from
--  Network.Socket. The SockAddr from Network.Socket corresponds to
--  @struct sockaddr_in@ in BSD terminology. The SockAddr record here
--  is BDS's @struct sockaddr@. See W.R.Stevens, TCP Illustrated, volume 2,
--  for further eluciadation.
--
--  This binding should be portable for systems that can use the libpcap
--  from tcpdump.org. It will not work with Winpcap, a similar library
--  for Windows, although adapting it should not prove difficult.
--
------------------------------------------------------------------------------



module Pcap (

	-- * Types
	Pcap,
	Pdump,
	BpfProgram,
	Callback,
	Link(..),
	Interface(..),
	PcapAddr(..),
	SockAddr(..),
	Network(..),
	PktHdr(..),
	Statistics(..),

	-- * Device opening
	openOffline,		-- :: String -> IO Pcap
	openLive,		-- :: String -> Int -> Bool -> Int -> IO Pcap
	openDead,		-- :: Int    -> Int -> IO Pcap
	openDump,		-- :: Ptr PcapTag -> String -> IO Pdump

	-- * Filter handling
	setFilter,		-- :: Ptr PcapTag -> String -> Bool -> Word32 -> IO ()
	compileFilter,		-- :: Int -> Int  -> String -> Bool -> Word32 -> IO BpfProgram

	-- * Device utilities
	lookupDev,		-- :: IO String
	findAllDevs,		-- :: IO [Interface]
	lookupNet,		-- :: String -> IO Network

	-- * Interface control
	-- ** Blocking mode
	setNonBlock,		-- :: Ptr PcapTag -> Bool -> IO ()
	getNonBlock,		-- :: Ptr PcapTag -> IO Bool

	-- ** Link layer utilities
	datalink,		-- :: Ptr PcapTag -> IO Link
	setDatalink,		-- :: Ptr PcapTag -> Link -> IO ()
	listDatalinks,		-- :: Ptr PcapTag -> IO [Link]

	-- * Packet processing
	dispatch,		-- :: Ptr PcapTag -> Int -> Callback -> IO Int
	loop,			-- :: Ptr PcapTag -> Int -> Callback -> IO Int
	next,			-- :: Ptr PcapTag -> IO (PktHdr, Ptr Word8)
	dump,			-- :: Ptr PcapDumpTag -> Ptr PktHdr -> Ptr Word8 -> IO ()

	-- * Miscellaneous
	statistics,		-- :: Ptr PcapTag -> IO Statistics
	majorVersion,		-- :: Ptr PcapTag -> IO Int
	minorVersion,		-- :: Ptr PcapTag -> IO Int
	isSwapped,		-- :: Ptr PcapTag -> IO Bool
	snapshotLen,		-- :: Ptr PcapTag -> IO Int
) where

import Maybe (isNothing, fromJust  )
import Data.Word ( Word8, Word32 )
import Foreign.Ptr ( Ptr, plusPtr, nullPtr, FunPtr, freeHaskellFunPtr )
import Foreign.C.String ( peekCString, withCString )
import Foreign.C.Types ( CInt, CUInt, CChar, CUChar, CLong )
import Foreign.ForeignPtr ( ForeignPtr, FinalizerPtr, newForeignPtr )
import Foreign.Marshal.Alloc ( alloca, allocaBytes, free )
import Foreign.Marshal.Array ( allocaArray, peekArray )
import Foreign.Marshal.Utils ( fromBool, toBool )
import Foreign.Storable ( Storable(..) )
import Network.Socket ( Family(..), unpackFamily)
import System.IO.Error ( userError )

#include <pcap.h>
#include <pcap-bpf.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "config.h"


data BpfProgramTag
-- | Compiled Berkeley Packet Filter program
type BpfProgram = ForeignPtr BpfProgramTag

data PcapTag
-- | packet capture descriptor
type Pcap  = ForeignPtr PcapTag

data PcapDumpTag
-- | savefile descriptor
type Pdump = ForeignPtr PcapDumpTag

data PktHdr    = PktHdr    { sec    :: Word32,	-- ^ timestamp (seconds)
			     usec   :: Word32,	-- ^ timestamp (microseconds)
			     caplen :: Word32,	-- ^ number of bytes present in capture
			     len    :: Word32 	-- ^ number of bytes on the wire
			   }
		deriving (Show)

data Statistics = Statistics { recv   :: Word32,	-- ^ packets received
			       drop   :: Word32,	-- ^ packets dropped by libpcap
			       ifdrop :: Word32		-- ^ packets dropped by the interface
			     }
		deriving (Show)


--
-- Data types for interface list
--

-- | The interface structure
data Interface = Interface { ifName        :: String,		-- ^ the interface name
                             ifDescription :: String,		-- ^ interface description string (if any)
                             ifAddresses   :: [PcapAddr],	-- ^ address families supported by this interface
                             ifFlags       :: Word32
                           }
		deriving (Read, Show)

-- | The address structure
data PcapAddr = PcapAddr { ifAddr  :: SockAddr,		-- ^ interface address
                           ifMask  :: Maybe SockAddr,	-- ^ network mask
                           ifBcast :: Maybe SockAddr,	-- ^ broadcast address
                           ifPeer  :: Maybe SockAddr	-- ^ address of peer, of a point-to-point link
                         }
		deriving (Read, Show)

-- |
--   The socket address record. Note that this is not the same as
--   SockAddr from Network.Sockets. (That is a Haskell version of
--   struct sockaddr_in. This is the real struct sockaddr from the BSD
--   network stack.)
--
data SockAddr = SockAddr { sockAddrFamily  :: Family,	-- ^ an address family exported by Network.Socket
			   sockAddrAddr    :: [Word8]
			 }
		deriving (Read, Show)

-- | The network address record. Both the address and mask are in
--   network byte order.
data Network = Network { netAddr :: Word32,	-- ^ IPv4 network address
			 netMask :: Word32	-- ^ IPv4 netmask
		       }
		deriving (Read, Show)


--
-- Open a device
--

-- |
--   openOffline opens a \"savefile\" for reading. The file foramt is the
--   as used for tcpdump. The string \"-\" is a synonym for stdin.
--
openOffline
	:: String	-- ^ filename
	-> IO Pcap
openOffline name =
        withCString name                      $ \namePtr ->
        allocaArray (#const PCAP_ERRBUF_SIZE) $ \errPtr  -> do
                ptr <- pcap_open_offline namePtr errPtr
                if ptr == nullPtr
                        then peekCString errPtr >>= ioError . userError
                        else do
                                final <- h2c pcap_close
                                newForeignPtr final ptr

-- |
--  openLive is used to get a packet descriptor that can be used to
--  look at packates on the network. The arguments are the device name,
--  the snapshot legnth (in bytes), the promiscuity of the interface
--  (True == promiscuous) and a timeout in milliseconds.
--
--  Using \"any\" as the device name will capture packets from all interfaces.
--  On some systems, reading from the \"any\" device is incompatible with
--  setting the interfaces into promiscuous mode. In that case, only packets
--  whose link layer addresses match those of the interfaces are captured.
--
openLive
	:: String	-- ^ device name
	-> Int		-- ^ snapshot length
	-> Bool		-- ^ set to promiscuous mode?
	-> Int		-- ^ timeout in milliseconds
	-> IO Pcap
openLive name snaplen promisc timeout =
        withCString name                      $ \namePtr ->
        allocaArray (#const PCAP_ERRBUF_SIZE) $ \errPtr  -> do
                ptr <- pcap_open_live namePtr
				      (fromIntegral snaplen)
				      (fromBool promisc)
				      (fromIntegral timeout)
				      errPtr
                if ptr == nullPtr
                        then peekCString errPtr >>= ioError . userError
                        else do
                                final <- h2c pcap_close
                                newForeignPtr final ptr

-- |
--   openDead is used to get a packet capture descriptor without opening
--   a file or device. It is typically used to test packet filter compilation
--   by setFilter. The arguments are the linktype and the snapshot length.
--
openDead
	:: Link		-- ^ datalink type
	-> Int		-- ^ snapshot length
	-> IO Pcap	-- ^ packet capture descriptor
openDead link snaplen = 
        do
                ptr <- pcap_open_dead (packLink link)
				      (fromIntegral snaplen)
                if ptr == nullPtr
                        then ioError $ userError "Can't open dead pcap device"
                        else do
                                final <- h2c pcap_close
                                newForeignPtr final ptr


foreign import ccall unsafe pcap_open_offline :: Ptr CChar   -> Ptr CChar -> IO (Ptr PcapTag)
foreign import ccall unsafe pcap_close        :: Ptr PcapTag -> IO ()
foreign import ccall unsafe pcap_open_live    :: Ptr CChar -> CInt -> CInt -> CInt -> Ptr CChar -> IO (Ptr PcapTag)
foreign import ccall unsafe pcap_open_dead    :: CInt -> CInt -> IO (Ptr PcapTag)

foreign import ccall "wrapper" h2c            :: (Ptr PcapTag -> IO()) -> IO (FinalizerPtr a)



--
-- Open a dump device
--

-- |
--   openDump opens a \"savefile\" for writing. This savefile is written to
--   by the dump function. The arguments are a raw packet capture descriptor
--   and the filename, with \"-\" as a synonym for stdout.
--
openDump
	:: Ptr PcapTag	-- ^ packet capture descriptor
	-> String	-- ^ savefile name
	-> IO Pdump	-- ^ davefile descriptor
openDump hdl name =
        withCString name $ \namePtr -> do
                ptr <- pcap_dump_open hdl namePtr
		if (ptr == nullPtr) then
			throwPcapError hdl
		    else do
			final <- h2c' pcap_dump_close
			newForeignPtr final ptr

foreign import ccall unsafe pcap_dump_open  :: Ptr PcapTag -> Ptr CChar -> IO (Ptr PcapDumpTag)
foreign import ccall unsafe pcap_dump_close :: Ptr PcapDumpTag -> IO ()

foreign import ccall "wrapper" h2c'         :: (Ptr PcapDumpTag -> IO()) -> IO (FinalizerPtr a)


--
-- Set the filter
--

-- |
--   Set a filter on the specified packet capture descriptor. Valid filter
--   strings are those accepted by tcpdump.
--
setFilter
	:: Ptr PcapTag	-- ^ packet capture descriptor
	-> String	-- ^ filter string
	-> Bool		-- ^ optimize?
	-> Word32	-- ^ IPv4 network mask
	-> IO ()
setFilter hdl filt opt mask =
        withCString filt $ \filter -> do
		allocaBytes (#size struct bpf_program) $ \bpfp -> do
			ret <- pcap_compile hdl
					    bpfp
					    filter
					    (fromBool opt)
					    (fromIntegral mask)
			if ret == (-1) then
				throwPcapError hdl
		    	    else do
				ret <- pcap_setfilter hdl bpfp
				if ret == (-1) then
					throwPcapError hdl
			 	  else
					pcap_freecode bpfp

-- |
--   Compile a filter for use by another program using the Berkeley Packet
--   Filter library.
--
compileFilter
	:: Int		-- ^ snapshot length
	-> Link		-- ^ datalink type
	-> String	-- ^ filter string
	-> Bool		-- ^ optimize?
	-> Word32	-- ^ IPv4 network mask
	-> IO BpfProgram
compileFilter snaplen link filt opt mask =
	withCString filt $ \filter ->
		allocaBytes (#size struct bpf_program) $ \bpfp -> do
			ret  <- pcap_compile_nopcap (fromIntegral snaplen)
				 		    (packLink link)
						    bpfp
				        	    filter
						    (fromBool opt)
						    (fromIntegral mask)
			if ret == (-1) then
				ioError $ userError "Pcap.compileFilter error"
		 	   else do
                         	final <- h2c'' pcap_freecode
                         	newForeignPtr final bpfp
	

foreign import ccall pcap_compile
	:: Ptr PcapTag  -> Ptr BpfProgramTag -> Ptr CChar -> CInt -> CInt -> IO CInt
foreign import ccall pcap_compile_nopcap
        :: CInt -> CInt -> Ptr BpfProgramTag -> Ptr CChar -> CInt -> CInt -> IO CInt
foreign import ccall pcap_setfilter
	:: Ptr PcapTag  -> Ptr BpfProgramTag -> IO CInt
foreign import ccall pcap_freecode
	:: Ptr BpfProgramTag -> IO ()

foreign import ccall "wrapper" h2c''
	:: (Ptr BpfProgramTag -> IO ()) -> IO (FinalizerPtr a)



--
-- Find devices
--

data DevBuf
data DevAddr


-- |
--   lookupDev returns the name of a device suitable for use with
--   openLive and lookupNet. If you only have one interface, it is the
--   function of choice. If not, see findAllDevs.
--
lookupDev :: IO String
lookupDev =
        allocaArray (#const PCAP_ERRBUF_SIZE) $ \errPtr  -> do
                ptr <- pcap_lookupdev errPtr
                if ptr == nullPtr
                        then peekCString errPtr >>= ioError . userError
                        else peekCString ptr


-- |
--   findAllDevs returns a list of all the network devices that can
--   be opened by openLive. It returns only those devices that the
--   calling process has sufficient privileges to open, so it may not
--   find every device on the system.
--
findAllDevs :: IO [Interface]
findAllDevs = 
	alloca $ \dptr -> do
		allocaArray (#const PCAP_ERRBUF_SIZE) $ \errPtr -> do
		        ret <- pcap_findalldevs dptr errPtr
		        if (ret == -1) then
                                peekCString errPtr >>= ioError . userError
                      	    else do
				dbuf <- peek dptr
				dl   <- devs2list dbuf
			        pcap_freealldevs dbuf
				return dl


devs2list :: Ptr DevBuf -> IO [Interface]
devs2list dbuf
	| dbuf == nullPtr       = do return []
	| otherwise		= do
		nextdev <- (#peek struct pcap_if, next) dbuf
		ds      <- devs2list nextdev
		d       <- oneDev dbuf
		return (d : ds)


oneDev :: Ptr DevBuf -> IO Interface
oneDev dbuf =
	do
		name  <- (#peek struct pcap_if, name) dbuf
		desc  <- (#peek struct pcap_if, description) dbuf
		addrs <- (#peek struct pcap_if, addresses) dbuf
		flags <- (#peek struct pcap_if, flags) dbuf

		name' <- peekCString name
		desc' <- if desc /= nullPtr then
				peekCString desc
			     else
				return ""

		addrs' <- addrs2list addrs

		return (Interface name' desc' addrs' (fromIntegral (flags :: CUInt)))


addrs2list :: Ptr DevAddr -> IO [PcapAddr]
addrs2list abuf
	| abuf == nullPtr       = do return []
	| otherwise		= do
		nextaddr <- (#peek struct pcap_addr, next) abuf
		as       <- addrs2list nextaddr
		a        <- oneAddr abuf
		return (a : as)


oneAddr :: Ptr DevAddr -> IO PcapAddr
oneAddr abuf =
	let
		socka :: Ptr a -> IO (Maybe SockAddr)
		socka sa =
			if sa /= nullPtr then
				do
#if defined(SA_LEN)
                                        l <- ((#peek struct sockaddr, sa_len) sa) :: IO CUChar
#else
                                        l <- return (#size struct sockaddr) :: IO CUChar
#endif
					f <- ((#peek struct sockaddr, sa_family) sa) :: IO CUChar
					
					addr <- peekArray ((fromIntegral l) - (#offset struct sockaddr, sa_data))
							   ((plusPtr sa (#offset struct sockaddr, sa_data)) :: Ptr Word8)

					return (Just (SockAddr (unpackFamily (fromIntegral f)) addr))
		    	    else
				return Nothing
	in	
		do
			addr  <- (#peek struct pcap_addr, addr) abuf      >>= socka
			mask  <- (#peek struct pcap_addr, netmask) abuf   >>= socka
			bcast <- (#peek struct pcap_addr, broadaddr) abuf >>= socka
			peer  <- (#peek struct pcap_addr, dstaddr) abuf   >>= socka

			if isNothing addr then
				ioError $ userError "Pcap.oneAddr: null address"
			    else
				return (PcapAddr (fromJust addr) mask bcast peer)


-- | Return the network address and mask for the specified interface
--   name. Only valid for IPv4. For other protocols,
--   use findAllDevs and search the Address list for the associated
--   network mask.
--
lookupNet
	:: String	-- ^ device name
	-> IO Network
lookupNet dev =
	withCString dev $ \name  ->
		alloca  $ \netp  ->
		alloca  $ \maskp -> do
			allocaArray (#const PCAP_ERRBUF_SIZE) $ \errPtr -> do
				ret  <- pcap_lookupnet name netp maskp errPtr
				if ret == (-1) then
					peekCString errPtr >>= ioError . userError
			            else do
					net  <- peek netp
					mask <- peek maskp

					return (Network (fromIntegral net)
							(fromIntegral mask) )


foreign import ccall unsafe pcap_lookupdev   :: Ptr CChar        -> IO (Ptr CChar)
foreign import ccall unsafe pcap_findalldevs :: Ptr (Ptr DevBuf) -> Ptr CChar -> IO CInt
foreign import ccall unsafe pcap_freealldevs :: Ptr DevBuf       -> IO ()
foreign import ccall unsafe pcap_lookupnet   :: Ptr CChar        -> Ptr CUInt -> Ptr CUInt -> Ptr CChar -> IO CInt



--
-- Set or read the device mode (blocking/nonblocking)
--

-- | Set a packet capture descriptor into non-blocking mode, if the
--   second argument is True, otherwise put it in blocking mode. Note
--   that the packet capture descripto must have been obtaine from openLive.
--
setNonBlock :: Ptr PcapTag -> Bool -> IO ()
setNonBlock ptr block = 
        allocaArray (#const PCAP_ERRBUF_SIZE) $ \errPtr  -> do
                ret <- pcap_setnonblock ptr (fromBool block) errPtr
                if ret == (-1)
                        then peekCString errPtr >>= ioError . userError
                        else return ()

--
-- | Return the blocking status of the packet capture descriptor. Ture
--   indicates that the descriptor is non-blocking. Descriptors referring
--   savefiles opened by openDump always reutre False.
--
getNonBlock :: Ptr PcapTag -> IO Bool
getNonBlock ptr = 
        allocaArray (#const PCAP_ERRBUF_SIZE) $ \errPtr  -> do
                ret <- pcap_getnonblock ptr errPtr
                if ret == (-1)
                        then peekCString errPtr >>= ioError . userError
                        else return (toBool ret)


foreign import ccall unsafe pcap_setnonblock :: Ptr PcapTag -> CInt -> Ptr CChar -> IO CInt
foreign import ccall unsafe pcap_getnonblock :: Ptr PcapTag -> Ptr CChar -> IO CInt



--
-- Error handling
--

throwPcapError :: Ptr PcapTag -> IO a
throwPcapError hdl = do
        msg <- pcap_geterr hdl >>= peekCString
        ioError (userError msg)


foreign import ccall unsafe pcap_geterr :: Ptr PcapTag -> IO (Ptr CChar)



--
-- Reading packets
--

-- | the type of the callback function passed to dispatch or loop.
type Callback  = PktHdr    -> Ptr Word8  -> IO ()
type CCallback = Ptr Word8 -> Ptr PktHdr -> Ptr Word8 -> IO ()


exportCallback :: Callback -> IO (FunPtr CCallback)
exportCallback f = exportCCallback $ \_user hdr ptr -> do
        let ts = (#ptr struct pcap_pkthdr, ts) hdr

        s      <- (#peek struct timeval,     tv_sec)  ts
        us     <- (#peek struct timeval,     tv_usec) ts
        caplen <- (#peek struct pcap_pkthdr, caplen)  hdr
        len    <- (#peek struct pcap_pkthdr, len)     hdr

	f
		(PktHdr
			(fromIntegral (s      :: CLong))
			(fromIntegral (us     :: CLong))
			(fromIntegral (caplen :: CUInt))
			(fromIntegral (len    :: CUInt)))
	 	ptr


-- |
--   Collect and process packets. The arguments are the packet capture
--   descriptor, the count and a callback function.
--
--   The count is the maximum number of packets to process before returning.
--   A count of -1 means process all of the packets received in one buffer
--   (if a live capture) or all of the packets in a savefile (if offline).
--
--   The callback function is passed two arguments, a packet header
--   record and a pointer to the packet data (Ptr Word8). THe header
--   record contains the number of bytes captured, whcih can be used
--   to marshal the data into a list or array.
--
dispatch
	:: Ptr PcapTag	-- ^ packet capture descriptor
	-> Int		-- ^ number of packets to process
	-> Callback	-- ^ packet processing function
	-> IO Int	-- ^ number of packets read
dispatch hdl count f = do
        handler <- exportCallback f
        result  <- pcap_dispatch hdl (fromIntegral count) handler nullPtr

        freeHaskellFunPtr handler

	if (result == -1) then
		throwPcapError hdl
	    else
	        return (fromIntegral result)


-- |
--   Similar to dispatch, but loop until the number of packets specified
--   by the second argument are read. A negative value loops forever.
--
--   It does not return when a live read tiemout occurs. Use dispatch instead
--   if you wnat to specify a timeout.
--
loop
	:: Ptr PcapTag	-- ^ packet cpature descriptor
	-> Int		-- ^ number of packet to read
	-> Callback	-- ^ packet processing function
	-> IO Int	-- ^ number of packets read
loop hdl count f = do
        handler <- exportCallback f
        result  <- pcap_loop hdl (fromIntegral count) handler nullPtr

        freeHaskellFunPtr handler

	if (result == -1) then
		throwPcapError hdl
	    else
	        return (fromIntegral result)


-- | 
--   Read the next packet (by calling dispatch with a count of 1).
--
next
	:: Ptr PcapTag			-- ^ packet capture descriptor
	-> IO (PktHdr, Ptr Word8)	-- ^ packet header and data of the next packet
next hdl =
        allocaBytes (#size struct pcap_pkthdr) $ \hdr -> do
                ptr <- pcap_next hdl hdr
                if (ptr == nullPtr) then
                        return (PktHdr 0 0 0 0, ptr)
                     else do
                        let ts = (#ptr struct pcap_pkthdr, ts) hdr

                        s      <- (#peek struct timeval,     tv_sec)  ts
                        us     <- (#peek struct timeval,     tv_usec) ts
                        caplen <- (#peek struct pcap_pkthdr, caplen)  hdr
                        len    <- (#peek struct pcap_pkthdr, len)     hdr

		        return (PktHdr
			          (fromIntegral (s      :: CLong))
			          (fromIntegral (us     :: CLong))
			          (fromIntegral (caplen :: CUInt))
			          (fromIntegral (len    :: CUInt)),
                                ptr)
				

-- |
--   Write the packet data given by the second and third arguments
--   to a savefile opened by openDead. dump is designed so it can be
--   easily used as a default callback function by dispatch or loop.
--
dump
	:: Ptr PcapDumpTag	-- ^ savefile descriptor
	-> Ptr PktHdr		-- ^ packet header record
	-> Ptr Word8		-- ^ packet data
	-> IO ()
dump hdl hdr pkt = pcap_dump hdl hdr pkt



foreign import ccall "wrapper" exportCCallback
        :: CCallback -> IO (FunPtr CCallback)

foreign import ccall pcap_dispatch
        :: Ptr PcapTag -> CInt -> FunPtr CCallback -> Ptr Word8 -> IO CInt
foreign import ccall pcap_loop
        :: Ptr PcapTag -> CInt -> FunPtr CCallback -> Ptr Word8 -> IO CInt
foreign import ccall pcap_next
        :: Ptr PcapTag -> Ptr PktHdr -> IO (Ptr Word8)
foreign import ccall pcap_dump
	:: Ptr PcapDumpTag -> Ptr PktHdr -> Ptr Word8 -> IO ()


--
-- Datalink manipulation
--

-- |
--   Returns the datalink type associated with the given pcap descriptor.
--
datalink :: Ptr PcapTag -> IO Link
datalink hdl = do
	ret <- pcap_datalink hdl
	return (unpackLink ret)


-- |
--   Sets the datalink type for a given pcap descriptor.
--
setDatalink :: Ptr PcapTag -> Link -> IO ()
setDatalink hdl link = do
	ret <- pcap_set_datalink hdl (packLink link)
	if (ret == -1) then
		throwPcapError hdl
	   else
		return ()


-- |
--   List all the datalink types supported by a pcap descriptor. Entries
--   from the resulting list are valid arguments to setDatalink.
--
listDatalinks :: Ptr PcapTag -> IO [Link]
listDatalinks hdl =
	alloca $ \lptr -> do
		ret <- pcap_list_datalinks hdl lptr
		if (ret == -1) then
			throwPcapError hdl
	    	    else do
			dlbuf <- peek lptr
			dls   <- peekArray (fromIntegral (ret :: CInt)) dlbuf
			free dlbuf
			return (map unpackLink dls)
	
		
foreign import ccall unsafe pcap_datalink       :: Ptr PcapTag -> IO CInt
foreign import ccall unsafe pcap_set_datalink   :: Ptr PcapTag -> CInt -> IO CInt
foreign import ccall unsafe pcap_list_datalinks :: Ptr PcapTag -> Ptr (Ptr CInt) -> IO CInt


--
-- Statistics
--

data PcapStats = PcapStats

-- |
--   Returns the number of packets received, the number of packets
--   dropped by the packet filter and the number of packets dropped
--   by the interface (before processing by the packet filter).
--
statistics :: Ptr PcapTag -> IO Statistics
statistics hdl =
	allocaBytes (#size struct pcap_stat) $ \stats -> do
                ret <- pcap_stats hdl stats
                if (ret == -1) then
			throwPcapError hdl
		    else do
			recv   <- (#peek struct pcap_stat, ps_recv) stats
			drop   <- (#peek struct pcap_stat, ps_drop) stats
			ifdrop <- (#peek struct pcap_stat, ps_ifdrop) stats

			return (Statistics
				(fromIntegral (recv   :: CUInt))
				(fromIntegral (drop   :: CUInt))
				(fromIntegral (ifdrop :: CUInt)))

foreign import ccall unsafe pcap_stats :: Ptr PcapTag -> Ptr PcapStats -> IO Int



--
-- Version information
--

-- |
--   Major version number of the library.
--
majorVersion :: Ptr PcapTag -> IO Int
majorVersion ptr = do
	v <- pcap_major_version ptr
	return (fromIntegral (v :: CInt))


-- |
--   Minor version number of the library.
--
minorVersion :: Ptr PcapTag -> IO Int
minorVersion ptr = do
	v <- pcap_major_version ptr
	return (fromIntegral (v :: CInt))


-- |
--   isSwapped is True if the current savefile uses a different
--   byte order than the one native to the system.
--
isSwapped :: Ptr PcapTag -> IO Bool
isSwapped ptr = do
        sw <- pcap_is_swapped ptr
        return (toBool sw)


-- |
--   The snapshot length that was used in the call to openLive.
-- 
snapshotLen :: Ptr PcapTag -> IO Int
snapshotLen ptr = do
	l <- pcap_snapshot ptr
	return (fromIntegral (l :: CInt))


foreign import ccall pcap_major_version :: Ptr PcapTag -> IO CInt
foreign import ccall pcap_minor_version :: Ptr PcapTag -> IO CInt
foreign import ccall pcap_is_swapped    :: Ptr PcapTag -> IO CInt
foreign import ccall pcap_snapshot      :: Ptr PcapTag -> IO CInt


--
-- Utility functions for data link types
--

-- | Datalink types.
--
--   This covers all of the datalink types defined in bpf.h.
--   Types defined on your system may vary.
--
data Link 
	= DLT_NULL		-- ^ no link layer encapsulation
#ifdef DLT_EN10MB
	| DLT_EN10MB		-- ^ 10 Mbit per second (or faster) ethernet
#endif
#ifdef DLT_EN3MB
	| DLT_EN3MB		-- ^ original 3 Mbit per second ethernet
#endif
#ifdef DLT_AX25
	| DLT_AX25		-- ^ amateur radio AX.25
#endif
#ifdef DLT_PRONET
	| DLT_PRONET		-- ^ Proteon ProNET Token Ring
#endif
#ifdef DLT_CHAOS
	| DLT_CHAOS		-- ^ Chaos
#endif
#ifdef DLT_IEEE802
	| DLT_IEEE802		-- ^ IEEE 802 networks
#endif
#ifdef DLT_ARCNET
	| DLT_ARCNET		-- ^ ARCNET
#endif
#ifdef DLT_SLIP
	| DLT_SLIP		-- ^ Serial line IP
#endif
#ifdef DLT_PPP
	| DLT_PPP		-- ^ Point-to-point protocol
#endif
#ifdef DLT_FDDI
	| DLT_FDDI		-- ^ FDDI
#endif
#ifdef DLT_ATM_RFC1483
	| DLT_ATM_RFC1483	-- ^ LLC SNAP encapsulated ATM
#endif
#ifdef DLT_RAW
	| DLT_RAW		-- ^ raw IP
#endif
#ifdef DLT_SLIP_BSDOS
	| DLT_SLIP_BSDOS	-- ^ BSD OS serial line IP
#endif
#ifdef DLT_PPP_BSDOS
	| DLT_PPP_BSDOS		-- ^ BSD OS point-to-point protocol
#endif
#ifdef DLT_ATM_CLIP
	| DLT_ATM_CLIP		-- ^ Linux classical IP over ATM
#endif
#ifdef DLT_PPP_SERIAL
	| DLT_PPP_SERIAL	-- ^ PPP over serial with HDLC encapsulation
#endif
#ifdef DLT_PPP_ETHER
	| DLT_PPP_ETHER		-- ^ PPP over ethernet
#endif
#ifdef DLT_C_HDLC		
	| DLT_C_HDLC		-- ^ Cisco HDLC
#endif
#ifdef DLT_IEEE802_11
	| DLT_IEEE802_11	-- ^ IEEE 802.11 wireless
#endif
#ifdef DLT_LOOP
	| DLT_LOOP		-- ^ OpenBSD loopback device
#endif
#ifdef DLT_LINUX_SLL
	| DLT_LINUX_SLL		-- ^ Linux cooked sockets
#endif
#ifdef DLT_LTALK
	| DLT_LTALK		-- ^ Apple LocalTalk
#endif
#ifdef DLT_ECONET
	| DLT_ECONET		-- ^ Acorn Econet
#endif
#ifdef DLT_IPFILTER
	| DLT_IPFILTER		-- ^ OpenBSD's old ipfilter
#endif
#ifdef DLT_PFLOG
	| DLT_PFLOG		-- ^ OpenBSD's pflog
#endif
#ifdef DLT_CISCO_IOS
	| DLT_CISCO_IOS		-- ^ Cisco IOS
#endif
#ifdef DLT_PRISM_HEADER
	| DLT_PRISM_HEADER	-- ^ Intersil Prism II wireless chips
#endif
#ifdef DLT_AIRONET_HEADER
	| DLT_AIRONET_HEADER	-- ^ Aironet (Cisco) 802.11 wireless
#endif
	deriving (Eq, Ord, Read, Show)


packLink :: Link -> CInt
packLink l = case l of
	DLT_NULL -> #const DLT_NULL
#ifdef DLT_EN10MB
	DLT_EN10MB	-> #const DLT_EN10MB
#endif
#ifdef DLT_EN3MB
	DLT_EN3MB	-> #const DLT_EN3MB
#endif
#ifdef DLT_AX25
	DLT_AX25	-> #const DLT_AX25
#endif
#ifdef DLT_PRONET
	DLT_PRONET	-> #const DLT_PRONET
#endif
#ifdef DLT_CHAOS
	DLT_CHAOS	-> #const DLT_CHAOS
#endif
#ifdef DLT_IEEE802
	DLT_IEEE802	-> #const DLT_IEEE802
#endif
#ifdef DLT_ARCNET
	DLT_ARCNET	-> #const DLT_ARCNET
#endif
#ifdef DLT_SLIP
	DLT_SLIP	-> #const DLT_SLIP
#endif
#ifdef DLT_PPP
	DLT_PPP		-> #const DLT_PPP
#endif
#ifdef DLT_FDDI
	DLT_FDDI	-> #const DLT_FDDI
#endif
#ifdef DLT_ATM_RFC1483
	DLT_ATM_RFC1483	-> #const DLT_ATM_RFC1483
#endif
#ifdef DLT_RAW
	DLT_RAW		-> #const DLT_RAW
#endif
#ifdef DLT_SLIP_BSDOS
	DLT_SLIP_BSDOS	-> #const DLT_SLIP_BSDOS
#endif
#ifdef DLT_PPP_BSDOS
	DLT_PPP_BSDOS	-> #const DLT_PPP_BSDOS
#endif
#ifdef DLT_ATM_CLIP
	DLT_ATM_CLIP	-> #const DLT_ATM_CLIP
#endif
#ifdef DLT_PPP_SERIAL
	DLT_PPP_SERIAL	-> #const DLT_PPP_SERIAL
#endif
#ifdef DLT_PPP_ETHER
	DLT_PPP_ETHER	-> #const DLT_PPP_ETHER
#endif
#ifdef DLT_C_HDLC		
	DLT_C_HDLC	-> #const DLT_C_HDLC
#endif
#ifdef DLT_IEEE802_11
	DLT_IEEE802_11	-> #const DLT_IEEE802_11
#endif
#ifdef DLT_LOOP
	DLT_LOOP	-> #const DLT_LOOP
#endif
#ifdef DLT_LINUX_SLL
	DLT_LINUX_SLL	-> #const DLT_LINUX_SLL
#endif
#ifdef DLT_LTALK
	DLT_LTALK	-> #const DLT_LTALK
#endif
#ifdef DLT_ECONET
	DLT_ECONET	-> #const DLT_ECONET
#endif
#ifdef DLT_IPFILTER
	DLT_IPFILTER	-> #const DLT_IPFILTER
#endif
#ifdef DLT_PFLOG
	DLT_PFLOG	-> #const DLT_PFLOG
#endif
#ifdef DLT_CISCO_IOS
	DLT_CISCO_IOS	-> #const DLT_CISCO_IOS
#endif
#ifdef DLT_PRISM_HEADER
	DLT_PRISM_HEADER -> #const DLT_PRISM_HEADER
#endif
#ifdef DLT_AIRONET_HEADER
	DLT_AIRONET_HEADER -> #const DLT_AIRONET_HEADER
#endif



unpackLink :: CInt -> Link
unpackLink l = case l of
	(#const DLT_NULL) 	-> DLT_NULL
#ifdef DLT_EN10MB
	(#const DLT_EN10MB)	-> DLT_EN10MB
#endif
#ifdef DLT_EN3MB
	(#const DLT_EN3MB)	-> DLT_EN3MB
#endif
#ifdef DLT_AX25
	(#const DLT_AX25)	-> DLT_AX25
#endif
#ifdef DLT_PRONET
	(#const DLT_PRONET)	-> DLT_PRONET
#endif
#ifdef DLT_CHAOS
	(#const DLT_CHAOS)	-> DLT_CHAOS
#endif
#ifdef DLT_IEEE802
	(#const DLT_IEEE802)	-> DLT_IEEE802
#endif
#ifdef DLT_ARCNET
	(#const DLT_ARCNET)	-> DLT_ARCNET
#endif
#ifdef DLT_SLIP
	(#const DLT_SLIP)	-> DLT_SLIP
#endif
#ifdef DLT_PPP
	(#const DLT_PPP)	-> DLT_PPP
#endif
#ifdef DLT_FDDI
	(#const DLT_FDDI)	-> DLT_FDDI
#endif
#ifdef DLT_ATM_RFC1483
	(#const DLT_ATM_RFC1483) -> DLT_ATM_RFC1483
#endif
#ifdef DLT_RAW
	(#const DLT_RAW)	-> DLT_RAW
#endif
#ifdef DLT_SLIP_BSDOS
	(#const DLT_SLIP_BSDOS)	-> DLT_SLIP_BSDOS
#endif
#ifdef DLT_PPP_BSDOS
	(#const DLT_PPP_BSDOS)	-> DLT_PPP_BSDOS
#endif
#ifdef DLT_ATM_CLIP
	(#const DLT_ATM_CLIP)	-> DLT_ATM_CLIP
#endif
#ifdef DLT_PPP_SERIAL
	(#const DLT_PPP_SERIAL)	-> DLT_PPP_SERIAL
#endif
#ifdef DLT_PPP_ETHER
	(#const DLT_PPP_ETHER)	-> DLT_PPP_ETHER
#endif
#ifdef DLT_C_HDLC		
	(#const DLT_C_HDLC)	-> DLT_C_HDLC
#endif
#ifdef DLT_IEEE802_11
	(#const DLT_IEEE802_11)	-> DLT_IEEE802_11
#endif
#ifdef DLT_LOOP
	(#const DLT_LOOP)	-> DLT_LOOP
#endif
#ifdef DLT_LINUX_SLL
	(#const DLT_LINUX_SLL)	-> DLT_LINUX_SLL
#endif
#ifdef DLT_LTALK
	(#const DLT_LTALK)	-> DLT_LTALK
#endif
#ifdef DLT_ECONET
	(#const DLT_ECONET)	-> DLT_ECONET
#endif
#ifdef DLT_IPFILTER
	(#const DLT_IPFILTER)	-> DLT_IPFILTER
#endif
#ifdef DLT_PFLOG
	(#const DLT_PFLOG)	-> DLT_PFLOG
#endif
#ifdef DLT_CISCO_IOS
	(#const DLT_CISCO_IOS)	-> DLT_CISCO_IOS
#endif
#ifdef DLT_PRISM_HEADER
	(#const DLT_PRISM_HEADER) -> DLT_PRISM_HEADER
#endif
#ifdef DLT_AIRONET_HEADER
	(#const DLT_AIRONET_HEADER) -> DLT_AIRONET_HEADER
#endif
