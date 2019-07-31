package re.frida;

public interface EatableWithField {
    String getName();
    int getCalories(int grams);
    public static final int MAX_CALORIES = 9000;
}
