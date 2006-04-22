module Main where

import Pcap
import Foreign

main = 
   do
      let printIt :: PktHdr -> Ptr Word8 -> IO ()
          printIt ph bytep = 
             do a <- peekArray (fromIntegral (caplen ph)) bytep
                print a
      p <- openLive "eth0" 100 True 10000
      s <- withForeignPtr p (\ptr -> do dispatch ptr (-1) printIt)
      return ()
