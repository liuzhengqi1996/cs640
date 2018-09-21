public class Client implements ThingThatRuns {
  String hostname;
  int port;
  int time; // in seconds

  public Client(String hostname, int port, int time) {
    this.hostname = hostname;
    this.port = port;
    this.time = time;
  }

  public void run() {

  }
}
