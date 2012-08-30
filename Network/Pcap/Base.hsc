{-# OPTIONS_GHC -fno-warn-unused-binds #-}
------------------------------------------------------------------------------
-- |
--  Module      : Network.Pcap.Base
--  Copyright   : Bryan O'Sullivan 2007, Antiope Associates LLC 2004
--  License     : BSD-style
--  Maintainer  : bos@serpentine.com
--  Stability   : experimental
--  Portability : non-portable
--
-- The 'Network.Pcap.Base' module is a low-level binding to all of the
-- functions in @libpcap@.  See <http://www.tcpdump.org> for more
-- information.
--
-- Only a minimum of marshaling is done.  For a higher-level interface
-- that\'s more friendly, use the 'Network.Pcap' module.
--
-- To convert captured packet data to a list, extract the length of
-- the captured buffer from the packet header record and use
-- 'peekArray' to convert the captured data to a list.  For
-- illustration:
--
-- > import Foreign
-- > import Network.Pcap.Base
-- >
-- > main :: IO ()
-- > main = do
-- >     p <- openLive "eth0" 100 True 10000
-- >     withForeignPtr p $ \ptr ->
-- >       dispatch ptr (-1) printIt
-- >     return ()
-- >
-- > printIt :: PktHdr -> Ptr Word8 -> IO ()
-- > printIt ph bytep =
-- >     peekArray (fromIntegral (hdrCaptureLength ph)) bytep >>= print
--
-- Note that the 'SockAddr' exported here is not the @SockAddr@ from
-- 'Network.Socket'. The @SockAddr@ from 'Network.Socket' corresponds
-- to @struct sockaddr_in@ in BSD terminology. The 'SockAddr' record
-- here is BSD's @struct sockaddr@. See W.R.Stevens, TCP Illustrated,
-- volume 2, for further elucidation.
--
-- This binding should be portable across systems that can use the
-- @libpcap@ library from @tcpdump.org@. It will not work with
-- Winpcap, a similar library for Windows, although adapting it should
-- not prove difficult.
--
------------------------------------------------------------------------------

module Network.Pcap.Base
    (
      -- * Types
      PcapTag
    , PcapDumpTag
    , Pdump
    , BpfProgram
    , BpfProgramTag
    , Callback
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
    , openDead                  -- :: Int    -> Int -> IO Pcap
    , openDump                  -- :: Ptr PcapTag -> FilePath -> IO Pdump

    -- * Filter handling
    , setFilter                 -- :: Ptr PcapTag -> String -> Bool -> Word32 -> IO ()
    , compileFilter             -- :: Int -> Int -> String -> Bool -> Word32 -> IO BpfProgram

    -- * Device utilities
    , lookupDev                 -- :: IO String
    , findAllDevs               -- :: IO [Interface]
    , lookupNet                 -- :: String -> IO Network

    -- * Interface control

    , setNonBlock               -- :: Ptr PcapTag -> Bool -> IO ()
    , getNonBlock               -- :: Ptr PcapTag -> IO Bool
    , setDirection

    -- * Link layer utilities
    , datalink                  -- :: Ptr PcapTag -> IO Link
    , setDatalink               -- :: Ptr PcapTag -> Link -> IO ()
    , listDatalinks             -- :: Ptr PcapTag -> IO [Link]

    -- * Packet processing
    , dispatch                  -- :: Ptr PcapTag -> Int -> Callback -> IO Int
    , loop                      -- :: Ptr PcapTag -> Int -> Callback -> IO Int
    , next                      -- :: Ptr PcapTag -> IO (PktHdr, Ptr Word8)
    , dump                      -- :: Ptr PcapDumpTag -> Ptr PktHdr -> Ptr Word8 -> IO ()

    -- * Sending packets
    , sendPacket

    -- * Conversion
    , toPktHdr

    -- * Miscellaneous
    , statistics                -- :: Ptr PcapTag -> IO Statistics
    , version                   -- :: Ptr PcapTag -> IO (Int, Int)
    , isSwapped                 -- :: Ptr PcapTag -> IO Bool
    , snapshotLen               -- :: Ptr PcapTag -> IO Int
    ) where

import Control.Monad (when)
import Data.Maybe (isNothing, fromJust )
import Data.ByteString ()
#ifdef BYTESTRING_IN_BASE
import qualified Data.ByteString.Base as B
#else
import qualified Data.ByteString.Internal as B
#endif
import Data.Word (Word8, Word32)
import Foreign.Ptr (Ptr, plusPtr, nullPtr, FunPtr, freeHaskellFunPtr)
import Foreign.C.String (CString, peekCString, withCString)
import Foreign.C.Types (CInt(..), CUInt, CChar, CUChar, CLong)
import Foreign.Concurrent (newForeignPtr)
import Foreign.ForeignPtr (ForeignPtr)
import Foreign.Marshal.Alloc (alloca, allocaBytes, free)
import Foreign.Marshal.Array (allocaArray, peekArray)
import Foreign.Marshal.Utils (fromBool, toBool)
import Foreign.Storable (Storable(..))
import Network.Socket (Family(..), unpackFamily)

#include <pcap.h>
#include <netinet/in.h>
#include <sys/socket.h>

newtype BpfProgramTag = BpfProgramTag ()

-- | Compiled Berkeley Packet Filter program.
type BpfProgram = ForeignPtr BpfProgramTag

newtype PcapTag = PcapTag ()

-- | Packet capture descriptor.
newtype PcapDumpTag = PcapDumpTag ()

-- | Dump file descriptor.
type Pdump = ForeignPtr PcapDumpTag

data PktHdr = PktHdr {
      hdrSeconds :: {-# UNPACK #-} !Word32       -- ^ timestamp (seconds)
    , hdrUseconds :: {-# UNPACK #-} !Word32      -- ^ timestamp (microseconds)
    , hdrCaptureLength :: {-# UNPACK #-} !Word32 -- ^ number of bytes present in capture
    , hdrWireLength :: {-# UNPACK #-} !Word32    -- ^ number of bytes on the wire
    } deriving (Eq, Show)

data Statistics = Statistics {
      statReceived :: {-# UNPACK #-} !Word32     -- ^ packets received
    , statDropped :: {-# UNPACK #-} !Word32      -- ^ packets dropped by @libpcap@
    , statIfaceDropped :: {-# UNPACK #-} !Word32 -- ^ packets dropped by the network interface
    } deriving (Eq, Show)

type ErrBuf = Ptr CChar

--
-- Data types for interface list
--

-- | The interface structure.
data Interface = Interface {
      ifName :: String          -- ^ the interface name
    , ifDescription :: String   -- ^ interface description string (if any)
    , ifAddresses :: [PcapAddr] -- ^ address families supported by this interface
    , ifFlags :: Word32
    } deriving (Eq, Read, Show)

-- | The address structure.
data PcapAddr = PcapAddr {
      addrSA  :: SockAddr         -- ^ interface address
    , addrMask  :: Maybe SockAddr -- ^ network mask
    , addrBcast :: Maybe SockAddr -- ^ broadcast address
    , addrPeer  :: Maybe SockAddr -- ^ address of peer, of a point-to-point link
    } deriving (Eq, Read, Show)

-- | The socket address record. Note that this is not the same as
-- SockAddr from 'Network.Socket'. (That is a Haskell version of C\'s
-- @struct sockaddr_in@. This is the real @struct sockaddr@ from the
-- BSD network stack.)
data SockAddr = SockAddr {
      saFamily  :: !Family       -- ^ an address family exported by Network.Socket
    , saAddr    :: {-# UNPACK #-} !B.ByteString
    } deriving (Eq, Read, Show)

-- | The network address record. Both the address and mask are in
-- network byte order.
data Network = Network {
      netAddr :: {-# UNPACK #-} !Word32 -- ^ IPv4 network address
    , netMask :: {-# UNPACK #-} !Word32 -- ^ IPv4 netmask
    } deriving (Eq, Read, Show)

withErrBuf :: (a -> Bool) -> (ErrBuf -> IO a) -> IO a
withErrBuf isError f = allocaArray (#const PCAP_ERRBUF_SIZE) $ \errPtr -> do
    ret <- f errPtr
    if isError ret
      then peekCString errPtr >>= ioError . userError
      else return ret

withErrBuf_ :: (a -> Bool) -> (ErrBuf -> IO a) -> IO ()
withErrBuf_ isError f = withErrBuf isError f >> return ()

-- | 'openOffline' opens a dump file for reading. The file format is
-- the same as used by @tcpdump@ and Wireshark. The string @\"-\"@ is
-- a synonym for @stdin@.
openOffline :: FilePath -- ^ filename
            -> IO (ForeignPtr PcapTag)
openOffline name =
    withCString name $ \namePtr -> do
      ptr <- withErrBuf (== nullPtr) (pcap_open_offline namePtr)
      newForeignPtr ptr (pcap_close ptr)

-- | 'openLive' is used to get a packet descriptor that can be used to
-- look at packets on the network. The arguments are the device name,
-- the snapshot length (in bytes), the promiscuity of the interface
-- ('True' == promiscuous) and a timeout in milliseconds.
--
-- Using @\"any\"@ as the device name will capture packets from all
-- interfaces.  On some systems, reading from the @\"any\"@ device is
-- incompatible with setting the interfaces into promiscuous mode. In
-- that case, only packets whose link layer addresses match those of
-- the interfaces are captured.
--
openLive :: String -- ^ device name
         -> Int    -- ^ snapshot length
         -> Bool   -- ^ set to promiscuous mode?
         -> Int    -- ^ timeout in milliseconds
         -> IO (ForeignPtr PcapTag)
openLive name snaplen promisc timeout =
    withCString name $ \namePtr -> do
      ptr <- withErrBuf (== nullPtr) $ pcap_open_live namePtr
             (fromIntegral snaplen) (fromBool promisc) (fromIntegral timeout)
      newForeignPtr ptr (pcap_close ptr)

-- | 'openDead' is used to get a packet capture descriptor without
-- opening a file or device. It is typically used to test packet
-- filter compilation by 'setFilter'. The arguments are the link type
-- and the snapshot length.
--
openDead :: Link                    -- ^ datalink type
         -> Int                     -- ^ snapshot length
         -> IO (ForeignPtr PcapTag) -- ^ packet capture descriptor
openDead link snaplen = do
    ptr <- pcap_open_dead (packLink link)
           (fromIntegral snaplen)
    when (ptr == nullPtr) $
        ioError $ userError "Can't open dead pcap device"
    newForeignPtr ptr (pcap_close ptr)

foreign import ccall unsafe pcap_open_offline
    :: CString   -> ErrBuf -> IO (Ptr PcapTag)
foreign import ccall unsafe pcap_close
    :: Ptr PcapTag -> IO ()
foreign import ccall unsafe pcap_open_live
    :: CString -> CInt -> CInt -> CInt -> ErrBuf -> IO (Ptr PcapTag)
foreign import ccall unsafe pcap_open_dead
    :: CInt -> CInt -> IO (Ptr PcapTag)

--
-- Open a dump device
--

-- | 'openDump' opens a dump file for writing. This dump file is
-- written to by the 'dump' function. The arguments are a raw packet
-- capture descriptor and the file name, with \"-\" as a synonym for
-- @stdout@.
openDump :: Ptr PcapTag -- ^ packet capture descriptor
         -> FilePath    -- ^ dump file name
         -> IO Pdump    -- ^ savefile descriptor
openDump hdl name =
    withCString name $ \namePtr -> do
      ptr <- pcap_dump_open hdl namePtr >>= throwPcapIf hdl (== nullPtr)
      newForeignPtr ptr (pcap_dump_close ptr)

foreign import ccall unsafe pcap_dump_open
    :: Ptr PcapTag -> CString -> IO (Ptr PcapDumpTag)
foreign import ccall unsafe pcap_dump_close
    :: Ptr PcapDumpTag -> IO ()

--
-- Set the filter
--

-- | Set a filter on the specified packet capture descriptor. Valid
-- filter strings are those accepted by @tcpdump@.
setFilter :: Ptr PcapTag -- ^ packet capture descriptor
          -> String      -- ^ filter string
          -> Bool        -- ^ optimize?
          -> Word32      -- ^ IPv4 network mask
          -> IO ()
setFilter hdl filt opt mask =
    withCString filt $ \filtstr -> do
      allocaBytes (#size struct bpf_program) $ \bpfp -> do
        pcap_compile hdl bpfp filtstr (fromBool opt) (fromIntegral mask) >>=
            throwPcapIf_ hdl (== -1)
        pcap_setfilter hdl bpfp >>= throwPcapIf_ hdl (== -1)
        pcap_freecode bpfp

-- | Compile a filter for use by another program using the Berkeley
-- Packet Filter library.
compileFilter :: Int    -- ^ snapshot length
              -> Link   -- ^ datalink type
              -> String -- ^ filter string
              -> Bool   -- ^ optimize?
              -> Word32 -- ^ IPv4 network mask
              -> IO BpfProgram
compileFilter snaplen link filt opt mask =
    withCString filt $ \filtstr ->
      allocaBytes (#size struct bpf_program) $ \bpfp -> do
        ret  <- pcap_compile_nopcap (fromIntegral snaplen)
                  (packLink link)
                  bpfp
                  filtstr
                  (fromBool opt)
                  (fromIntegral mask)
        when (ret == (-1)) $
            ioError $ userError "Pcap.compileFilter error"
        newForeignPtr bpfp (pcap_freecode bpfp)

foreign import ccall pcap_compile
        :: Ptr PcapTag  -> Ptr BpfProgramTag -> CString -> CInt -> CInt
        -> IO CInt
foreign import ccall pcap_compile_nopcap
        :: CInt -> CInt -> Ptr BpfProgramTag -> CString -> CInt -> CInt
        -> IO CInt
foreign import ccall pcap_setfilter
        :: Ptr PcapTag  -> Ptr BpfProgramTag -> IO CInt
foreign import ccall pcap_freecode
        :: Ptr BpfProgramTag -> IO ()

--
-- Find devices
--

newtype DevBuf = DevBuf ()
newtype DevAddr = DevAddr ()

-- | 'lookupDev' returns the name of a device suitable for use with
-- 'openLive' and 'lookupNet'. If you only have one interface, it is
-- the function of choice. If not, see 'findAllDevs'.
lookupDev :: IO String
lookupDev = withErrBuf (== nullPtr) pcap_lookupdev >>= peekCString

-- | 'findAllDevs' returns a list of all the network devices that can
-- be opened by 'openLive'. It returns only those devices that the
-- calling process has sufficient privileges to open, so it may not
-- find every device on the system.
findAllDevs :: IO [Interface]
findAllDevs =
    alloca $ \dptr -> do
      withErrBuf_ (== -1) (pcap_findalldevs dptr)
      dbuf <- peek dptr
      dl <- devs2list dbuf
      pcap_freealldevs dbuf
      return dl

devs2list :: Ptr DevBuf -> IO [Interface]
devs2list dbuf
    | dbuf == nullPtr = return []
    | otherwise = do
        nextdev <- (#peek struct pcap_if, next) dbuf
        ds <- devs2list nextdev
        d <- oneDev dbuf
        return (d : ds)

oneDev :: Ptr DevBuf -> IO Interface
oneDev dbuf = do
    name  <- (#peek struct pcap_if, name) dbuf
    desc  <- (#peek struct pcap_if, description) dbuf
    addrs <- (#peek struct pcap_if, addresses) dbuf
    flags <- (#peek struct pcap_if, flags) dbuf

    name' <- peekCString name
    desc' <- if desc /= nullPtr
             then peekCString desc
             else return ""

    addrs' <- addrs2list addrs

    return Interface { ifName = name'
                     , ifDescription = desc'
                     , ifAddresses = addrs'
                     , ifFlags = fromIntegral (flags :: CUInt)
                     }

addrs2list :: Ptr DevAddr -> IO [PcapAddr]
addrs2list abuf
    | abuf == nullPtr = return []
    | otherwise = do
        nextaddr <- (#peek struct pcap_addr, next) abuf
        as <- addrs2list nextaddr
        a <- oneAddr abuf
        return (a : as)

oneAddr :: Ptr DevAddr -> IO PcapAddr
oneAddr abuf =
    let socka :: Ptr a -> IO (Maybe SockAddr)
        socka sa | sa == nullPtr = return Nothing
                 | otherwise = do
#if defined(HAVE_STRUCT_SOCKADDR_SA_LEN)
          l <- ((#peek struct sockaddr, sa_len) sa) :: IO CUChar
#else
          l <- return (#size struct sockaddr) :: IO CUChar
#endif
          f <- ((#peek struct sockaddr, sa_family) sa) :: IO CUChar

          let off = (#offset struct sockaddr, sa_data)
              nbytes = ((fromIntegral l) - off)
          addr <- B.create nbytes $ \p ->
                  B.memcpy p (plusPtr sa off :: Ptr Word8)
                       (fromIntegral nbytes)

          return (Just (SockAddr (unpackFamily (fromIntegral f)) addr))
    in do
      addr <- socka =<< (#peek struct pcap_addr, addr) abuf

      when (isNothing addr) $
           ioError $ userError "Pcap.oneAddr: null address"

      mask <- socka =<< (#peek struct pcap_addr, netmask) abuf
      bcast <- socka =<< (#peek struct pcap_addr, broadaddr) abuf
      peer <- socka =<< (#peek struct pcap_addr, dstaddr) abuf

      return PcapAddr { addrSA = fromJust addr
                      , addrMask = mask
                      , addrBcast = bcast
                      , addrPeer = peer
                      }

-- | Return the network address and mask for the specified interface
-- name. Only valid for IPv4. For other protocols, use 'findAllDevs'
-- and search the 'Interface' list for the associated network mask.
lookupNet :: String     -- ^ device name
          -> IO Network
lookupNet dev = withCString dev $ \name  ->
    alloca $ \netp -> alloca $ \maskp -> do
      withErrBuf_ (== -1) (pcap_lookupnet name netp maskp)
      net  <- peek netp
      mask <- peek maskp

      return Network { netAddr = fromIntegral net
                     , netMask = fromIntegral mask
                     }

foreign import ccall unsafe pcap_lookupdev
    :: CString -> IO CString
foreign import ccall unsafe pcap_findalldevs
    :: Ptr (Ptr DevBuf) -> ErrBuf -> IO CInt
foreign import ccall unsafe pcap_freealldevs
    :: Ptr DevBuf -> IO ()
foreign import ccall unsafe pcap_lookupnet
    :: CString -> Ptr CUInt -> Ptr CUInt -> ErrBuf -> IO CInt

--
-- Set or read the device mode (blocking/nonblocking)
--

-- | Set a packet capture descriptor into non-blocking mode if the
-- second argument is 'True', otherwise put it in blocking mode. Note
-- that the packet capture descriptor must have been obtained from
-- 'openLive'.
--
setNonBlock :: Ptr PcapTag -> Bool -> IO ()
setNonBlock hdl block =
    withErrBuf_ (== -1) (pcap_setnonblock hdl (fromBool block))

-- | Return the blocking status of the packet capture
-- descriptor. 'True' indicates that the descriptor is
-- non-blocking. Descriptors referring to dump files opened by
-- 'openDump' always return 'False'.
getNonBlock :: Ptr PcapTag -> IO Bool
getNonBlock hdl = toBool `fmap` withErrBuf (== -1) (pcap_getnonblock hdl)

-- | The direction in which packets are to be captured.  See
-- 'setDirection'.
data Direction = InOut -- ^ incoming and outgoing packets (the default)
               | In    -- ^ incoming packets
               | Out   -- ^ outgoing packets
                 deriving (Eq, Show, Read)

-- | Specify the direction in which packets are to be captured.
-- Complete functionality is not necessarily available on all
-- platforms.
setDirection :: Ptr PcapTag -> Direction -> IO ()
setDirection hdl dir =
    pcap_setdirection hdl (packDirection dir) >>= throwPcapIf_ hdl (== -1)

packDirection :: Direction -> CInt
packDirection In = (#const PCAP_D_IN)
packDirection Out = (#const PCAP_D_OUT)
packDirection InOut = (#const PCAP_D_INOUT)

foreign import ccall unsafe pcap_setnonblock
    :: Ptr PcapTag -> CInt -> ErrBuf -> IO CInt
foreign import ccall unsafe pcap_getnonblock
    :: Ptr PcapTag -> ErrBuf -> IO CInt
foreign import ccall unsafe pcap_setdirection
    :: Ptr PcapTag -> CInt -> IO CInt

--
-- Error handling
--

throwPcapIf :: Ptr PcapTag -> (a -> Bool) -> a -> IO a
throwPcapIf hdl p v = if p v
    then pcap_geterr hdl >>= peekCString >>= ioError . userError
    else return v

throwPcapIf_ :: Ptr PcapTag -> (a -> Bool) -> a -> IO ()
throwPcapIf_ hdl p v = throwPcapIf hdl p v >> return ()

foreign import ccall unsafe pcap_geterr
    :: Ptr PcapTag -> IO CString

-- | Send a raw packet through the network interface.
sendPacket :: Ptr PcapTag
           -> Ptr Word8 -- ^ packet data (including link-level header)
           -> Int       -- ^ packet size
           -> IO ()
sendPacket hdl buf size =
    pcap_sendpacket hdl buf (fromIntegral size) >>= throwPcapIf_ hdl (== -1)

foreign import ccall unsafe pcap_sendpacket
    :: Ptr PcapTag -> Ptr Word8 -> CInt -> IO CInt

-- | the type of the callback function passed to 'dispatch' or 'loop'.
type Callback  = PktHdr    -> Ptr Word8  -> IO ()
type CCallback = Ptr Word8 -> Ptr PktHdr -> Ptr Word8 -> IO ()

toPktHdr :: Ptr PktHdr -> IO PktHdr
toPktHdr hdr = do
    let ts = (#ptr struct pcap_pkthdr, ts) hdr

    s <- (#peek struct timeval, tv_sec) ts
    us <- (#peek struct timeval, tv_usec) ts
    caplen <- (#peek struct pcap_pkthdr, caplen) hdr
    len <- (#peek struct pcap_pkthdr, len) hdr

    return PktHdr { hdrSeconds = fromIntegral (s :: CLong)
                  , hdrUseconds = fromIntegral (us :: CLong)
                  , hdrCaptureLength = fromIntegral (caplen :: CUInt)
                  , hdrWireLength = fromIntegral (len :: CUInt)
                  }

exportCallback :: Callback -> IO (FunPtr CCallback)
exportCallback f = exportCCallback $ \_user chdr ptr -> do
    hdr <- toPktHdr chdr
    f hdr ptr

-- | Collect and process packets. The arguments are the packet capture
-- descriptor, the count and a callback function.
--
-- The count is the maximum number of packets to process before
-- returning.  A count of -1 means process all of the packets received
-- in one buffer (if a live capture) or all of the packets in a dump
-- file (if offline).
--
-- The callback function is passed two arguments, a packet header
-- record and a pointer to the packet data (@Ptr Word8@). The header
-- record contains the number of bytes captured, which can be used to
-- marshal the data into a list or array.
--
dispatch :: Ptr PcapTag -- ^ packet capture descriptor
         -> Int         -- ^ number of packets to process
         -> Callback    -- ^ packet processing function
         -> IO Int      -- ^ number of packets read
dispatch hdl count f = do
    handler <- exportCallback f
    result  <- pcap_dispatch hdl (fromIntegral count) handler nullPtr

    freeHaskellFunPtr handler

    fromIntegral `fmap` throwPcapIf hdl (== -1) result

-- | Similar to 'dispatch', but loop until the number of packets
-- specified by the second argument are read. A negative value loops
-- forever.
--
-- This function does not return when a live read timeout occurs. Use
-- 'dispatch' instead if you want to specify a timeout.
loop :: Ptr PcapTag -- ^ packet capture descriptor
     -> Int         -- ^ number of packet to read
     -> Callback    -- ^ packet processing function
     -> IO Int      -- ^ number of packets read
loop hdl count f = do
    handler <- exportCallback f
    result  <- pcap_loop hdl (fromIntegral count) handler nullPtr

    freeHaskellFunPtr handler

    fromIntegral `fmap` throwPcapIf hdl (== -1) result

-- | Read the next packet (equivalent to calling 'dispatch' with a
-- count of 1).
next :: Ptr PcapTag            -- ^ packet capture descriptor
     -> IO (PktHdr, Ptr Word8) -- ^ packet header and data of the next packet
next hdl =
    allocaBytes (#size struct pcap_pkthdr) $ \chdr -> do
      ptr <- pcap_next hdl chdr
      if (ptr == nullPtr)
        then return (PktHdr 0 0 0 0, ptr)
        else do
          hdr <- toPktHdr chdr
          return (hdr, ptr)

-- | Write the packet data given by the second and third arguments to
-- a dump file opened by 'openDead'. 'dump' is designed so it can be
-- easily used as a default callback function by 'dispatch' or 'loop'.
dump :: Ptr PcapDumpTag -- ^ dump file descriptor
     -> Ptr PktHdr      -- ^ packet header record
     -> Ptr Word8       -- ^ packet data
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

-- | Returns the datalink type associated with the given pcap
-- descriptor.
--
datalink :: Ptr PcapTag -> IO Link
datalink hdl = unpackLink `fmap` pcap_datalink hdl

-- | Sets the datalink type for a given pcap descriptor.
--
setDatalink :: Ptr PcapTag -> Link -> IO ()
setDatalink hdl link =
    pcap_set_datalink hdl (packLink link) >>= throwPcapIf_ hdl (== -1)

-- | List all the datalink types supported by a pcap descriptor.
-- Entries from the resulting list are valid arguments to
-- 'setDatalink'.
listDatalinks :: Ptr PcapTag -> IO [Link]
listDatalinks hdl =
    alloca $ \lptr -> do
      ret <- pcap_list_datalinks hdl lptr >>= throwPcapIf hdl (== -1)
      dlbuf <- peek lptr
      dls <- peekArray (fromIntegral (ret :: CInt)) dlbuf
      free dlbuf
      return (map unpackLink dls)

foreign import ccall unsafe pcap_datalink
    :: Ptr PcapTag -> IO CInt
foreign import ccall unsafe pcap_set_datalink
    :: Ptr PcapTag -> CInt -> IO CInt
foreign import ccall unsafe pcap_list_datalinks
    :: Ptr PcapTag -> Ptr (Ptr CInt) -> IO CInt

--
-- Statistics
--

-- | Returns the number of packets received, the number of packets
-- dropped by the packet filter and the number of packets dropped by
-- the interface (before processing by the packet filter).
--
statistics :: Ptr PcapTag -> IO Statistics
statistics hdl =
    allocaBytes (#size struct pcap_stat) $ \stats -> do
      pcap_stats hdl stats >>= throwPcapIf_ hdl (== -1)
      recv   <- (#peek struct pcap_stat, ps_recv) stats
      pdrop  <- (#peek struct pcap_stat, ps_drop) stats
      ifdrop <- (#peek struct pcap_stat, ps_ifdrop) stats

      return Statistics { statReceived = fromIntegral (recv :: CUInt)
                        , statDropped = fromIntegral (pdrop :: CUInt)
                        , statIfaceDropped = fromIntegral (ifdrop :: CUInt)
                        }

foreign import ccall unsafe pcap_stats
    :: Ptr PcapTag -> Ptr Statistics -> IO Int

-- | Version of the library.  The returned pair consists of the major
-- and minor version numbers.
version :: Ptr PcapTag -> IO (Int, Int)
version hdl = do
  major <- pcap_major_version hdl
  minor <- pcap_minor_version hdl
  return (fromIntegral major, fromIntegral minor)

-- | 'isSwapped' returns 'True' if the current dump file uses a
-- different byte order than the one native to the system.
isSwapped :: Ptr PcapTag -> IO Bool
isSwapped hdl = toBool `fmap` pcap_is_swapped hdl

-- | The snapshot length that was used in the call to 'openLive'.
snapshotLen :: Ptr PcapTag -> IO Int
snapshotLen hdl = fromIntegral `fmap` pcap_snapshot hdl

foreign import ccall pcap_major_version
    :: Ptr PcapTag -> IO CInt
foreign import ccall pcap_minor_version
    :: Ptr PcapTag -> IO CInt
foreign import ccall pcap_is_swapped
    :: Ptr PcapTag -> IO CInt
foreign import ccall pcap_snapshot
    :: Ptr PcapTag -> IO CInt

--
-- Utility functions for data link types
--

-- | Datalink types.
--
--   This covers all of the datalink types defined in bpf.h.  Types
--   defined on your system may vary.
--
data Link
    = DLT_NULL                          -- ^ no link layer encapsulation
    | DLT_UNKNOWN Int                   -- ^ unknown encapsulation
#ifdef DLT_EN10MB
    | DLT_EN10MB                        -- ^ 10 Mbit per second (or faster) ethernet
#endif
#ifdef DLT_EN3MB
    | DLT_EN3MB                         -- ^ original 3 Mbit per second ethernet
#endif
#ifdef DLT_AX25
    | DLT_AX25                          -- ^ amateur radio AX.25
#endif
#ifdef DLT_PRONET
    | DLT_PRONET                        -- ^ Proteon ProNET Token Ring
#endif
#ifdef DLT_CHAOS
    | DLT_CHAOS                         -- ^ Chaos
#endif
#ifdef DLT_IEEE802
    | DLT_IEEE802                       -- ^ IEEE 802 networks
#endif
#ifdef DLT_ARCNET
    | DLT_ARCNET                        -- ^ ARCNET
#endif
#ifdef DLT_SLIP
    | DLT_SLIP                          -- ^ Serial line IP
#endif
#ifdef DLT_PPP
    | DLT_PPP                           -- ^ Point-to-point protocol
#endif
#ifdef DLT_FDDI
    | DLT_FDDI                          -- ^ FDDI
#endif
#ifdef DLT_ATM_RFC1483
    | DLT_ATM_RFC1483                   -- ^ LLC SNAP encapsulated ATM
#endif
#ifdef DLT_RAW
    | DLT_RAW                           -- ^ raw IP
#endif
#ifdef DLT_SLIP_BSDOS
    | DLT_SLIP_BSDOS                    -- ^ BSD OS serial line IP
#endif
#ifdef DLT_PPP_BSDOS
    | DLT_PPP_BSDOS                     -- ^ BSD OS point-to-point protocol
#endif
#ifdef DLT_ATM_CLIP
    | DLT_ATM_CLIP                      -- ^ Linux classical IP over ATM
#endif
#ifdef DLT_REDBACK_SMARTEDGE
    | DLT_REDBACK_SMARTEDGE             -- ^ Redback SmartEdge 400\/800
#endif
#ifdef DLT_PPP_SERIAL
    | DLT_PPP_SERIAL                    -- ^ PPP over serial with HDLC encapsulation
#endif
#ifdef DLT_PPP_ETHER
    | DLT_PPP_ETHER                     -- ^ PPP over ethernet
#endif
#ifdef DLT_SYMANTEC_FIREWALL
    | DLT_SYMANTEC_FIREWALL             -- ^ Symantec Enterprise Firewall
#endif
#ifdef DLT_C_HDLC
    | DLT_C_HDLC                        -- ^ Cisco HDLC
#endif
#ifdef DLT_IEEE802_11
    | DLT_IEEE802_11                    -- ^ IEEE 802.11 wireless
#endif
#ifdef DLT_FRELAY
    | DLT_FRELAY                        -- ^ Frame Relay
#endif
#ifdef DLT_LOOP
    | DLT_LOOP                          -- ^ OpenBSD loopback device
#endif
#ifdef DLT_ENC
    | DLT_ENC                           -- ^ Encapsulated packets for IPsec
#endif
#ifdef DLT_LINUX_SLL
    | DLT_LINUX_SLL                     -- ^ Linux cooked sockets
#endif
#ifdef DLT_LTALK
    | DLT_LTALK                         -- ^ Apple LocalTalk
#endif
#ifdef DLT_ECONET
    | DLT_ECONET                        -- ^ Acorn Econet
#endif
#ifdef DLT_IPFILTER
    | DLT_IPFILTER                      -- ^ OpenBSD's old ipfilter
#endif
#ifdef DLT_PFLOG
    | DLT_PFLOG                         -- ^ OpenBSD's pflog
#endif
#ifdef DLT_CISCO_IOS
    | DLT_CISCO_IOS                     -- ^ Cisco IOS
#endif
#ifdef DLT_PRISM_HEADER
    | DLT_PRISM_HEADER                  -- ^ Intersil Prism II wireless chips
#endif
#ifdef DLT_AIRONET_HEADER
    | DLT_AIRONET_HEADER                -- ^ Aironet (Cisco) 802.11 wireless
#endif
#ifdef DLT_HHDLC
    | DLT_HHDLC                         -- ^ Siemens HiPath HDLC
#endif
#ifdef DLT_IP_OVER_FC
    | DLT_IP_OVER_FC                    -- ^ RFC 2625 IP-over-Fibre Channel
#endif
#ifdef DLT_SUNATM
    | DLT_SUNATM                        -- ^ Full Frontal ATM on Solaris with SunATM
#endif
#ifdef DLT_IEEE802_11_RADIO
    | DLT_IEEE802_11_RADIO              -- ^ 802.11 plus a number of bits of link-layer information
#endif
#ifdef DLT_ARCNET_LINUX
    | DLT_ARCNET_LINUX                  -- ^ Linux ARCNET header
#endif
#ifdef DLT_APPLE_IP_OVER_IEEE1394
    | DLT_APPLE_IP_OVER_IEEE1394        -- ^ Apple IP-over-IEEE 1394
#endif
#ifdef DLT_MTP2_WITH_PHDR
    | DLT_MTP2_WITH_PHDR                -- ^ SS7, C7 MTP2 with pseudo-header
#endif
#ifdef DLT_MTP2
    | DLT_MTP2                          -- ^ SS7, C7 Message Transfer Part 2 (MPT2)
#endif
#ifdef DLT_MTP3
    | DLT_MTP3                          -- ^ SS7, C7 Message Transfer Part 3 (MPT3)
#endif
#ifdef DLT_SCCP
    | DLT_SCCP                          -- ^ SS7, C7 SCCP
#endif
#ifdef DLT_DOCSIS
    | DLT_DOCSIS                        -- ^ DOCSIS MAC frame
#endif
#ifdef DLT_LINUX_IRDA
    | DLT_LINUX_IRDA                    -- ^ Linux IrDA packet
#endif
#ifdef DLT_USER0
    | DLT_USER0                         -- ^ Reserved for private use
#endif
#ifdef DLT_USER1
    | DLT_USER1                         -- ^ Reserved for private use
#endif
#ifdef DLT_USER2
    | DLT_USER2                         -- ^ Reserved for private use
#endif
#ifdef DLT_USER3
    | DLT_USER3                         -- ^ Reserved for private use
#endif
#ifdef DLT_USER4
    | DLT_USER4                         -- ^ Reserved for private use
#endif
#ifdef DLT_USER5
    | DLT_USER5                         -- ^ Reserved for private use
#endif
#ifdef DLT_USER6
    | DLT_USER6                         -- ^ Reserved for private use
#endif
#ifdef DLT_USER7
    | DLT_USER7                         -- ^ Reserved for private use
#endif
#ifdef DLT_USER8
    | DLT_USER8                         -- ^ Reserved for private use
#endif
#ifdef DLT_USER9
    | DLT_USER9                         -- ^ Reserved for private use
#endif
#ifdef DLT_USER10
    | DLT_USER10                        -- ^ Reserved for private use
#endif
#ifdef DLT_USER11
    | DLT_USER11                        -- ^ Reserved for private use
#endif
#ifdef DLT_USER12
    | DLT_USER12                        -- ^ Reserved for private use
#endif
#ifdef DLT_USER13
    | DLT_USER13                        -- ^ Reserved for private use
#endif
#ifdef DLT_USER14
    | DLT_USER14                        -- ^ Reserved for private use
#endif
#ifdef DLT_USER15
    | DLT_USER15                        -- ^ Reserved for private use
#endif
#ifdef DLT_PPP_PPPD
    | DLT_PPP_PPPD                      -- ^ Outgoing packets for ppp daemon
#endif
#ifdef DLT_GPRS_LLC
    | DLT_GPRS_LLC                      -- ^ GPRS LLC
#endif
#ifdef DLT_GPF_T
    | DLT_GPF_T                         -- ^ GPF-T (ITU-T G.7041\/Y.1303)
#endif
#ifdef DLT_GPF_F
    | DLT_GPF_F                         -- ^ GPF-F (ITU-T G.7041\/Y.1303)
#endif
#ifdef DLT_LINUX_LAPD
    | DLT_LINUX_LAPD                    -- ^ Raw LAPD for vISDN (/not/ generic LAPD)
#endif
#ifdef DLT_A429
    | DLT_A429                          -- ^ ARINC 429
#endif
#ifdef DLT_A653_ICM
    | DLT_A653_ICM                      -- ^ ARINC 653 Interpartition Communication messages
#endif
#ifdef DLT_USB
    | DLT_USB                           -- ^ USB packet
#endif
#ifdef DLT_BLUETOOTH_HCI_H4
    | DLT_BLUETOOTH_HCI_H4              -- ^ Bluetooth HCI UART transport layer (part H:4)
#endif
#ifdef DLT_MFR
    | DLT_MFR                           -- ^ Multi Link Frame Relay (FRF.16)
#endif
#ifdef DLT_IEEE802_16_MAC_CPS
    | DLT_IEEE802_16_MAC_CPS            -- ^ IEEE 802.16 MAC Common Part Sublayer
#endif
#ifdef DLT_USB_LINUX
    | DLT_USB_LINUX                     -- ^ USB packets, beginning with a Linux USB header
#endif
#ifdef DLT_CAN20B
    | DLT_CAN20B                        -- ^ Controller Area Network (CAN) v2.0B
#endif
#ifdef DLT_IEEE802_15_4_LINUX
    | DLT_IEEE802_15_4_LINUX            -- ^ IEEE 802.15.4, with address fields padded
#endif
#ifdef DLT_PPI
    | DLT_PPI                           -- ^ Per Packet Information encapsulated packets
#endif
#ifdef DLT_IEEE802_16_MAC_CPS_RADIO
    | DLT_IEEE802_16_MAC_CPS_RADIO      -- ^ 802.16 MAC Common Part Sublayer with radiotap radio header
#endif
#ifdef DLT_IEEE802_15_4
    | DLT_IEEE802_15_4                  -- ^ IEEE 802.15.4, exactly as in the spec
#endif
#ifdef DLT_PFSYNC
    | DLT_PFSYNC
#endif
    deriving (Eq, Ord, Read, Show)

packLink :: Link -> CInt
packLink l = case l of
#ifdef DLT_NULL
    DLT_NULL -> #const DLT_NULL
#endif
#ifdef DLT_EN10MB
    DLT_EN10MB -> #const DLT_EN10MB
#endif
#ifdef DLT_EN3MB
    DLT_EN3MB -> #const DLT_EN3MB
#endif
#ifdef DLT_AX25
    DLT_AX25 -> #const DLT_AX25
#endif
#ifdef DLT_PRONET
    DLT_PRONET -> #const DLT_PRONET
#endif
#ifdef DLT_CHAOS
    DLT_CHAOS -> #const DLT_CHAOS
#endif
#ifdef DLT_IEEE802
    DLT_IEEE802 -> #const DLT_IEEE802
#endif
#ifdef DLT_ARCNET
    DLT_ARCNET -> #const DLT_ARCNET
#endif
#ifdef DLT_SLIP
    DLT_SLIP -> #const DLT_SLIP
#endif
#ifdef DLT_PPP
    DLT_PPP -> #const DLT_PPP
#endif
#ifdef DLT_FDDI
    DLT_FDDI -> #const DLT_FDDI
#endif
#ifdef DLT_ATM_RFC1483
    DLT_ATM_RFC1483 -> #const DLT_ATM_RFC1483
#endif
#ifdef DLT_RAW
    DLT_RAW -> #const DLT_RAW
#endif
#ifdef DLT_SLIP_BSDOS
    DLT_SLIP_BSDOS -> #const DLT_SLIP_BSDOS
#endif
#ifdef DLT_PPP_BSDOS
    DLT_PPP_BSDOS -> #const DLT_PPP_BSDOS
#endif
#ifdef DLT_ATM_CLIP
    DLT_ATM_CLIP -> #const DLT_ATM_CLIP
#endif
#ifdef DLT_REDBACK_SMARTEDGE
    DLT_REDBACK_SMARTEDGE -> #const DLT_REDBACK_SMARTEDGE
#endif
#ifdef DLT_PPP_SERIAL
    DLT_PPP_SERIAL -> #const DLT_PPP_SERIAL
#endif
#ifdef DLT_PPP_ETHER
    DLT_PPP_ETHER -> #const DLT_PPP_ETHER
#endif
#ifdef DLT_SYMANTEC_FIREWALL
    DLT_SYMANTEC_FIREWALL -> #const DLT_SYMANTEC_FIREWALL
#endif
#ifdef DLT_C_HDLC
    DLT_C_HDLC -> #const DLT_C_HDLC
#endif
#ifdef DLT_IEEE802_11
    DLT_IEEE802_11 -> #const DLT_IEEE802_11
#endif
#ifdef DLT_FRELAY
    DLT_FRELAY -> #const DLT_FRELAY
#endif
#ifdef DLT_LOOP
    DLT_LOOP -> #const DLT_LOOP
#endif
#ifdef DLT_ENC
    DLT_ENC -> #const DLT_ENC
#endif
#ifdef DLT_LINUX_SLL
    DLT_LINUX_SLL -> #const DLT_LINUX_SLL
#endif
#ifdef DLT_LTALK
    DLT_LTALK -> #const DLT_LTALK
#endif
#ifdef DLT_ECONET
    DLT_ECONET -> #const DLT_ECONET
#endif
#ifdef DLT_IPFILTER
    DLT_IPFILTER -> #const DLT_IPFILTER
#endif
#ifdef DLT_OLD_PFLOG
    DLT_OLD_PFLOG -> #const DLT_OLD_PFLOG
#endif
#ifdef DLT_PFSYNC
    DLT_PFSYNC -> #const DLT_PFSYNC
#endif
#ifdef DLT_PFLOG
    DLT_PFLOG -> #const DLT_PFLOG
#endif
#ifdef DLT_CISCO_IOS
    DLT_CISCO_IOS -> #const DLT_CISCO_IOS
#endif
#ifdef DLT_PRISM_HEADER
    DLT_PRISM_HEADER -> #const DLT_PRISM_HEADER
#endif
#ifdef DLT_AIRONET_HEADER
    DLT_AIRONET_HEADER -> #const DLT_AIRONET_HEADER
#endif
#ifdef DLT_HHDLC
    DLT_HHDLC -> #const DLT_HHDLC
#endif
#ifdef DLT_IP_OVER_FC
    DLT_IP_OVER_FC -> #const DLT_IP_OVER_FC
#endif
#ifdef DLT_SUNATM
    DLT_SUNATM -> #const DLT_SUNATM
#endif
#ifdef DLT_IEEE802_11_RADIO
    DLT_IEEE802_11_RADIO -> #const DLT_IEEE802_11_RADIO
#endif
#ifdef DLT_ARCNET_LINUX
    DLT_ARCNET_LINUX -> #const DLT_ARCNET_LINUX
#endif
#ifdef DLT_APPLE_IP_OVER_IEEE1394
    DLT_APPLE_IP_OVER_IEEE1394 -> #const DLT_APPLE_IP_OVER_IEEE1394
#endif
#ifdef DLT_MTP2_WITH_PHDR
    DLT_MTP2_WITH_PHDR -> #const DLT_MTP2_WITH_PHDR
#endif
#ifdef DLT_MTP2
    DLT_MTP2 -> #const DLT_MTP2
#endif
#ifdef DLT_MTP3
    DLT_MTP3 -> #const DLT_MTP3
#endif
#ifdef DLT_SCCP
    DLT_SCCP -> #const DLT_SCCP
#endif
#ifdef DLT_DOCSIS
    DLT_DOCSIS -> #const DLT_DOCSIS
#endif
#ifdef DLT_LINUX_IRDA
    DLT_LINUX_IRDA -> #const DLT_LINUX_IRDA
#endif
#ifdef DLT_USER0
    DLT_USER0 -> #const DLT_USER0
#endif
#ifdef DLT_USER1
    DLT_USER1 -> #const DLT_USER1
#endif
#ifdef DLT_USER2
    DLT_USER2 -> #const DLT_USER2
#endif
#ifdef DLT_USER3
    DLT_USER3 -> #const DLT_USER3
#endif
#ifdef DLT_USER4
    DLT_USER4 -> #const DLT_USER4
#endif
#ifdef DLT_USER5
    DLT_USER5 -> #const DLT_USER5
#endif
#ifdef DLT_USER6
    DLT_USER6 -> #const DLT_USER6
#endif
#ifdef DLT_USER7
    DLT_USER7 -> #const DLT_USER7
#endif
#ifdef DLT_USER8
    DLT_USER8 -> #const DLT_USER8
#endif
#ifdef DLT_USER9
    DLT_USER9 -> #const DLT_USER9
#endif
#ifdef DLT_USER10
    DLT_USER10 -> #const DLT_USER10
#endif
#ifdef DLT_USER11
    DLT_USER11 -> #const DLT_USER11
#endif
#ifdef DLT_USER12
    DLT_USER12 -> #const DLT_USER12
#endif
#ifdef DLT_USER13
    DLT_USER13 -> #const DLT_USER13
#endif
#ifdef DLT_USER14
    DLT_USER14 -> #const DLT_USER14
#endif
#ifdef DLT_USER15
    DLT_USER15 -> #const DLT_USER15
#endif
#ifdef DLT_PPP_PPPD
    DLT_PPP_PPPD -> #const DLT_PPP_PPPD
#endif
#ifdef DLT_GPRS_LLC
    DLT_GPRS_LLC -> #const DLT_GPRS_LLC
#endif
#ifdef DLT_GPF_T
    DLT_GPF_T -> #const DLT_GPF_T
#endif
#ifdef DLT_GPF_F
    DLT_GPF_F -> #const DLT_GPF_F
#endif
#ifdef DLT_LINUX_LAPD
    DLT_LINUX_LAPD -> #const DLT_LINUX_LAPD
#endif
#ifdef DLT_MFR
    DLT_MFR -> #const DLT_MFR
#endif
#ifdef DLT_A429
    DLT_A429 -> #const DLT_A429
#endif
#ifdef DLT_A653_ICM
    DLT_A653_ICM -> #const DLT_A653_ICM
#endif
#ifdef DLT_USB
    DLT_USB -> #const DLT_USB
#endif
#ifdef DLT_BLUETOOTH_HCI_H4
    DLT_BLUETOOTH_HCI_H4 -> #const DLT_BLUETOOTH_HCI_H4
#endif
#ifdef DLT_IEEE802_16_MAC_CPS
    DLT_IEEE802_16_MAC_CPS -> #const DLT_IEEE802_16_MAC_CPS
#endif
#ifdef DLT_USB_LINUX
    DLT_USB_LINUX -> #const DLT_USB_LINUX
#endif
#ifdef DLT_CAN20B
    DLT_CAN20B -> #const DLT_CAN20B
#endif
#ifdef DLT_IEEE802_15_4_LINUX
    DLT_IEEE802_15_4_LINUX -> #const DLT_IEEE802_15_4_LINUX
#endif
#ifdef DLT_PPI
    DLT_PPI -> #const DLT_PPI
#endif
#ifdef DLT_IEEE802_16_MAC_CPS_RADIO
    DLT_IEEE802_16_MAC_CPS_RADIO -> #const DLT_IEEE802_16_MAC_CPS_RADIO
#endif
#ifdef DLT_IEEE802_15_4
    DLT_IEEE802_15_4 -> #const DLT_IEEE802_15_4
#endif
#ifdef DLT_IEEE802_15_4
    DLT_UNKNOWN _ -> error "cannot pack unknown link type"
#endif

unpackLink :: CInt -> Link
unpackLink l = case l of
#ifdef DLT_NULL
    (#const DLT_NULL) -> DLT_NULL
#endif
#ifdef DLT_EN10MB
    (#const DLT_EN10MB) -> DLT_EN10MB
#endif
#ifdef DLT_EN3MB
    (#const DLT_EN3MB) -> DLT_EN3MB
#endif
#ifdef DLT_AX25
    (#const DLT_AX25) -> DLT_AX25
#endif
#ifdef DLT_PRONET
    (#const DLT_PRONET) -> DLT_PRONET
#endif
#ifdef DLT_CHAOS
    (#const DLT_CHAOS) -> DLT_CHAOS
#endif
#ifdef DLT_IEEE802
    (#const DLT_IEEE802) -> DLT_IEEE802
#endif
#ifdef DLT_ARCNET
    (#const DLT_ARCNET) -> DLT_ARCNET
#endif
#ifdef DLT_SLIP
    (#const DLT_SLIP) -> DLT_SLIP
#endif
#ifdef DLT_PPP
    (#const DLT_PPP) -> DLT_PPP
#endif
#ifdef DLT_FDDI
    (#const DLT_FDDI) -> DLT_FDDI
#endif
#ifdef DLT_ATM_RFC1483
    (#const DLT_ATM_RFC1483) -> DLT_ATM_RFC1483
#endif
#ifdef DLT_RAW
    (#const DLT_RAW) -> DLT_RAW
#endif
#ifdef DLT_SLIP_BSDOS
    (#const DLT_SLIP_BSDOS) -> DLT_SLIP_BSDOS
#endif
#ifdef DLT_PPP_BSDOS
    (#const DLT_PPP_BSDOS) -> DLT_PPP_BSDOS
#endif
#ifdef DLT_ATM_CLIP
    (#const DLT_ATM_CLIP) -> DLT_ATM_CLIP
#endif
#ifdef DLT_REDBACK_SMARTEDGE
    (#const DLT_REDBACK_SMARTEDGE) -> DLT_REDBACK_SMARTEDGE
#endif
#ifdef DLT_PPP_SERIAL
    (#const DLT_PPP_SERIAL) -> DLT_PPP_SERIAL
#endif
#ifdef DLT_PPP_ETHER
    (#const DLT_PPP_ETHER) -> DLT_PPP_ETHER
#endif
#ifdef DLT_SYMANTEC_FIREWALL
    (#const DLT_SYMANTEC_FIREWALL) -> DLT_SYMANTEC_FIREWALL
#endif
#ifdef DLT_C_HDLC
    (#const DLT_C_HDLC) -> DLT_C_HDLC
#endif
#ifdef DLT_IEEE802_11
    (#const DLT_IEEE802_11) -> DLT_IEEE802_11
#endif
#ifdef DLT_FRELAY
    (#const DLT_FRELAY) -> DLT_FRELAY
#endif
#ifdef DLT_LOOP
    (#const DLT_LOOP) -> DLT_LOOP
#endif
#ifdef DLT_ENC
    (#const DLT_ENC) -> DLT_ENC
#endif
#ifdef DLT_LINUX_SLL
    (#const DLT_LINUX_SLL) -> DLT_LINUX_SLL
#endif
#ifdef DLT_LTALK
    (#const DLT_LTALK) -> DLT_LTALK
#endif
#ifdef DLT_ECONET
    (#const DLT_ECONET) -> DLT_ECONET
#endif
#ifdef DLT_IPFILTER
    (#const DLT_IPFILTER) -> DLT_IPFILTER
#endif
#ifdef DLT_OLD_PFLOG
    (#const DLT_OLD_PFLOG) -> DLT_OLD_PFLOG
#endif
#ifdef DLT_PFSYNC
    (#const DLT_PFSYNC) -> DLT_PFSYNC
#endif
#ifdef DLT_PFLOG
    (#const DLT_PFLOG) -> DLT_PFLOG
#endif
#ifdef DLT_CISCO_IOS
    (#const DLT_CISCO_IOS) -> DLT_CISCO_IOS
#endif
#ifdef DLT_PRISM_HEADER
    (#const DLT_PRISM_HEADER) -> DLT_PRISM_HEADER
#endif
#ifdef DLT_AIRONET_HEADER
    (#const DLT_AIRONET_HEADER) -> DLT_AIRONET_HEADER
#endif
#ifdef DLT_HHDLC
    (#const DLT_HHDLC) -> DLT_HHDLC
#endif
#ifdef DLT_IP_OVER_FC
    (#const DLT_IP_OVER_FC) -> DLT_IP_OVER_FC
#endif
#ifdef DLT_SUNATM
    (#const DLT_SUNATM) -> DLT_SUNATM
#endif
#ifdef DLT_IEEE802_11_RADIO
    (#const DLT_IEEE802_11_RADIO) -> DLT_IEEE802_11_RADIO
#endif
#ifdef DLT_ARCNET_LINUX
    (#const DLT_ARCNET_LINUX) -> DLT_ARCNET_LINUX
#endif
#ifdef DLT_APPLE_IP_OVER_IEEE1394
    (#const DLT_APPLE_IP_OVER_IEEE1394) -> DLT_APPLE_IP_OVER_IEEE1394
#endif
#ifdef DLT_MTP2_WITH_PHDR
    (#const DLT_MTP2_WITH_PHDR) -> DLT_MTP2_WITH_PHDR
#endif
#ifdef DLT_MTP2
    (#const DLT_MTP2) -> DLT_MTP2
#endif
#ifdef DLT_MTP3
    (#const DLT_MTP3) -> DLT_MTP3
#endif
#ifdef DLT_SCCP
    (#const DLT_SCCP) -> DLT_SCCP
#endif
#ifdef DLT_DOCSIS
    (#const DLT_DOCSIS) -> DLT_DOCSIS
#endif
#ifdef DLT_LINUX_IRDA
    (#const DLT_LINUX_IRDA) -> DLT_LINUX_IRDA
#endif
#ifdef DLT_USER0
    (#const DLT_USER0) -> DLT_USER0
#endif
#ifdef DLT_USER1
    (#const DLT_USER1) -> DLT_USER1
#endif
#ifdef DLT_USER2
    (#const DLT_USER2) -> DLT_USER2
#endif
#ifdef DLT_USER3
    (#const DLT_USER3) -> DLT_USER3
#endif
#ifdef DLT_USER4
    (#const DLT_USER4) -> DLT_USER4
#endif
#ifdef DLT_USER5
    (#const DLT_USER5) -> DLT_USER5
#endif
#ifdef DLT_USER6
    (#const DLT_USER6) -> DLT_USER6
#endif
#ifdef DLT_USER7
    (#const DLT_USER7) -> DLT_USER7
#endif
#ifdef DLT_USER8
    (#const DLT_USER8) -> DLT_USER8
#endif
#ifdef DLT_USER9
    (#const DLT_USER9) -> DLT_USER9
#endif
#ifdef DLT_USER10
    (#const DLT_USER10) -> DLT_USER10
#endif
#ifdef DLT_USER11
    (#const DLT_USER11) -> DLT_USER11
#endif
#ifdef DLT_USER12
    (#const DLT_USER12) -> DLT_USER12
#endif
#ifdef DLT_USER13
    (#const DLT_USER13) -> DLT_USER13
#endif
#ifdef DLT_USER14
    (#const DLT_USER14) -> DLT_USER14
#endif
#ifdef DLT_USER15
    (#const DLT_USER15) -> DLT_USER15
#endif
#ifdef DLT_PPP_PPPD
    (#const DLT_PPP_PPPD) -> DLT_PPP_PPPD
#endif
#ifdef DLT_GPRS_LLC
    (#const DLT_GPRS_LLC) -> DLT_GPRS_LLC
#endif
#ifdef DLT_GPF_T
    (#const DLT_GPF_T) -> DLT_GPF_T
#endif
#ifdef DLT_GPF_F
    (#const DLT_GPF_F) -> DLT_GPF_F
#endif
#ifdef DLT_LINUX_LAPD
    (#const DLT_LINUX_LAPD) -> DLT_LINUX_LAPD
#endif
#ifdef DLT_MFR
    (#const DLT_MFR) -> DLT_MFR
#endif
#ifdef DLT_A429
    (#const DLT_A429) -> DLT_A429
#endif
#ifdef DLT_A653_ICM
    (#const DLT_A653_ICM) -> DLT_A653_ICM
#endif
#ifdef DLT_USB
    (#const DLT_USB) -> DLT_USB
#endif
#ifdef DLT_BLUETOOTH_HCI_H4
    (#const DLT_BLUETOOTH_HCI_H4) -> DLT_BLUETOOTH_HCI_H4
#endif
#ifdef DLT_IEEE802_16_MAC_CPS
    (#const DLT_IEEE802_16_MAC_CPS) -> DLT_IEEE802_16_MAC_CPS
#endif
#ifdef DLT_USB_LINUX
    (#const DLT_USB_LINUX) -> DLT_USB_LINUX
#endif
#ifdef DLT_CAN20B
    (#const DLT_CAN20B) -> DLT_CAN20B
#endif
#ifdef DLT_IEEE802_15_4_LINUX
    (#const DLT_IEEE802_15_4_LINUX) -> DLT_IEEE802_15_4_LINUX
#endif
#ifdef DLT_PPI
    (#const DLT_PPI) -> DLT_PPI
#endif
#ifdef DLT_IEEE802_16_MAC_CPS_RADIO
    (#const DLT_IEEE802_16_MAC_CPS_RADIO) -> DLT_IEEE802_16_MAC_CPS_RADIO
#endif
#ifdef DLT_IEEE802_15_4
    (#const DLT_IEEE802_15_4) -> DLT_IEEE802_15_4
#endif
#ifdef DLT_IEEE802_15_4
    unk -> DLT_UNKNOWN (fromIntegral unk)
#endif
