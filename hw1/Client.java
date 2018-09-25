import java.net.Socket;
import java.net.UnknownHostException;
import java.io.IOException;
import java.io.BufferedOutputStream;

public class Client implements Runnable {
  String hostname;
  int port;
  int milliseconds; // in milliseconds

  public Client(String hostname, int port, int time) {
    this.hostname = hostname;
    this.port = port;
    this.milliseconds = time * 1000;
  }

  public void run() {
    try {
      Socket socket = new Socket(this.hostname, this.port);
      BufferedOutputStream out = new BufferedOutputStream(socket.getOutputStream());
      byte message[] = new byte[1000];
      long startTime = System.currentTimeMillis();
      int kilobytesSent = 0;
      while (System.currentTimeMillis() < startTime + this.milliseconds) {
        System.out.println("Hello");
        out.write(message);
        kilobytesSent++;
      }
      socket.close();
      double mbps = ((double) kilobytesSent) / this.milliseconds;
      System.out.println(String.format("sent=%s KB rate=%s Mbps", kilobytesSent, mbps));
    } catch(UnknownHostException u) {
        System.out.println(u);
    } catch(IOException i) {
        System.out.println(i);
    }
  }
}
