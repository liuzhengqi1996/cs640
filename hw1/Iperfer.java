public class Iperfer {

  public static void main(String[] args) {
    System.out.println(args[0]);
    ThingThatRuns thingThatRuns;
    if (args[0].equals("-c")) {
      if (args.length != 7) {
        System.out.println("Error: missing or additional arguments");
        System.exit(0);
      }
      String hostname = args[2];
      int port = Integer.parseInt(args[4]);
      int time = Integer.parseInt(args[6]);
      validatePort(port);
      thingThatRuns = new Client(hostname, port, time);
    } else if (args[0].equals("-s")) {
      if (args.length != 3) {
        System.out.println("Error: missing or additional arguments");
        System.exit(0);
      }
      int port = Integer.parseInt(args[2]);
      validatePort(port);
      thingThatRuns = new Server(port);
    } else {
      return;
    }
    thingThatRuns.run();
  }

  private static void validatePort(int port) {
    if (port < 1024 || port > 65535) {
      System.out.println("Error: port number must be in the range 1024 to 65535");
      System.exit(0);
    }
  }
}
