package edu.uta.cse4382.demo;

/** Simple data object the service expects to receive as XML. */
public class Order {
    private String customer;
    private String item;
    private int quantity;

    public String getCustomer() { return customer; }
    public String getItem() { return item; }
    public int getQuantity() { return quantity; }

    @Override
    public String toString() {
        return "Order[customer=" + customer + ", item=" + item + ", quantity=" + quantity + "]";
    }
}
