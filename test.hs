module Main where

import Foreign
import Network.Pcap.Base

main :: IO ()
main = do
    p <- openLive "eth0" 100 True 10000
    withForeignPtr p $ \ptr ->
      dispatch ptr (-1) printIt
    return ()

printIt :: PktHdr -> Ptr Word8 -> IO ()
printIt ph bytep =
    peekArray (fromIntegral (hdrCaptureLength ph)) bytep >>= print
