import java.net.*;
import java.io.*;

public class Server implements Runnable {
  int port;
  char[] buffer;

  public Server(int port) {
    this.port = port;
    buffer = new char[1000];
  }

  public void run() {
    try(
    	ServerSocket ss = new ServerSocket(port);
    	Socket cs = ss.accept();
    	BufferedReader in = new BufferedReader(new InputStreamReader(cs.getInputStream()));
    		) {
    	long start = System.currentTimeMillis();
    	long runTime;
    	int kbTransfered = 0;
    	while(in.read(buffer, 0, 1000) != -1) {
    		kbTransfered++;
    	}
    	runTime = System.currentTimeMillis() - start;

    	System.out.printf("received=%d KB rate=%.3f Mbps\n", kbTransfered, ((double)kbTransfered)/runTime);
    } catch(IOException e) {
    }
  }
}
