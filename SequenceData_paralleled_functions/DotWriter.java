import java.io.FileWriter;
import java.io.IOException;

public class DotWriter {
    FileWriter myWriter;

	public DotWriter(String filename) {
        try {
            this.myWriter = new FileWriter(filename);
        } catch (IOException e) {
            System.out.println("An error occurred");
            e.printStackTrace();
        }
	}

    public void write(String mystring) { 
        try {
            this.myWriter.write(mystring);
        } catch (IOException e) {
            System.out.println("An error occurred");
            e.printStackTrace();
        }
    } 
    
    public void writeln(String mystring) { 
        try {
            this.myWriter.write(mystring + "\n");
        } catch (IOException e) {
            System.out.println("An error occurred");
            e.printStackTrace();
        }
    } 

    public void close() {
        try {
            this.myWriter.flush();
            this.myWriter.close();
        } catch (IOException e) {
            System.out.println("An error occurred");
            e.printStackTrace();
        }
    }
}
