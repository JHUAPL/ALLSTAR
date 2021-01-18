public class AttributedVertex {
	String id;
    String name;

	public AttributedVertex(String id, String name) {
		this.id = id;
        this.name = name;
	}


    @Override
    public String toString() { 
        return "\"" + id + "___" + name + "\"";
    } 
}
