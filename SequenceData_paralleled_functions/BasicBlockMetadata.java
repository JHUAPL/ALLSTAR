import java.util.ArrayList;

public class BasicBlockMetadata<X, Y, Z, W> {
	ArrayList<X> basicBlocks;
    ArrayList<Y> edges;
    ArrayList<Z> attributes;
    ArrayList<W> boundaries;

	public BasicBlockMetadata (ArrayList<X> basicBlocks, ArrayList<Y> edges, ArrayList<Z> attributes, ArrayList<W> boundaries) {
		this.basicBlocks = basicBlocks;
        this.edges = edges;
        this.attributes = attributes;
        this.boundaries = boundaries;
	}

    @Override
    public String toString() { 
        return "BasicBlockMetdata toString() to be implemented";
    } 
}
