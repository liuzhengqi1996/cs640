JFLAGS = -g
JC = javac
.SUFFIXES: .java .class
.java.class:
	$(JC) $(JFLAGS) $*.java

CLASSES = \
	Server.java \
	Client.java \
	Iperfer.java \
	Runnable.java 

default: classes

classes: $(CLASSES:.java=.class)

clean:
	$(RM) *.class
