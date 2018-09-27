import java.net.*;
import java.io.*;

public class Server implements Runnable {
  int port;
  byte[] buffer;

  public Server(int port) {
    this.port = port;
    buffer = new byte[1000];
  }

  public void run() {
    try {
    	ServerSocket ss = new ServerSocket(port);
    	Socket cs = ss.accept();
      DataInputStream in = new DataInputStream(cs.getInputStream());
    	long start = System.currentTimeMillis();
    	long runTime;
    	long bytesTransferred = 0;
    	while(true) {
        int bytesRead = in.read(buffer, 0, 1000);
        if (bytesRead != -1) {
          bytesTransferred += bytesRead;
        } else {
          break;
        }
    	}
    	runTime = System.currentTimeMillis() - start;

      long kilobytesTransferred = bytesTransferred/1000;
      double transferRate = bytesTransferred/(runTime*1000.0);

    	System.out.printf("received=%d KB rate=%.3f Mbps\n", kilobytesTransferred, transferRate);
    } catch(IOException e) {
      System.out.println(e);
    }
  }
}
