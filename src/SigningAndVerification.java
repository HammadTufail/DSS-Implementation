import java.math.*;
import java.util.*;

public class SigningAndVerification {

    public MyBigInteger[] sign(PrivateKey privateKey, PublicKey publicKey, String message){

        MyBigInteger signature[] = new MyBigInteger[2];
        MyBigInteger hash = new MyBigInteger(SHA.SHAHash(message), 16);

        RandomNumberGenerator random = new RandomNumberGenerator(System.currentTimeMillis());
        MyBigInteger k;
        do {
            k = new MyBigInteger(160, random);
        }while(k.bitLength() != 160 || k.gcd(publicKey.getQ()).compareTo(MyBigInteger.ONE) != 0 || k.compareTo(publicKey.getQ()) > 0);

        MyBigInteger k_inv = k.modInverse(publicKey.getQ());
        signature[0] = publicKey.getG().modPow(k, publicKey.getP()).mod(publicKey.getQ());
        MyBigInteger multi = privateKey.getA().multiply(signature[0]);
        MyBigInteger sum = multi.add(hash);
        signature[1] = k_inv.multiply(sum).mod(publicKey.getQ());

        return signature;
    }

    public boolean verify(MyBigInteger[] signature, String message, PublicKey publicKey){

        MyBigInteger hash = new MyBigInteger(SHA.SHAHash(message), 16);
        MyBigInteger w =  signature[1].modInverse(publicKey.getQ());
        MyBigInteger u1 = hash.multiply(w).mod(publicKey.getQ());
        MyBigInteger u2 = (signature[0].multiply(w)).mod(publicKey.getQ());

        MyBigInteger t1 = publicKey.getG().modPow(u1, publicKey.getP());
        MyBigInteger t2 = publicKey.getB().modPow(u2, publicKey.getP());
        MyBigInteger t3 = t1.multiply(t2);
        MyBigInteger t4 = t3.mod(publicKey.getP());
        MyBigInteger t  = t4.mod(publicKey.getQ());

        return  t.compareTo(signature[0]) == 0;

    }
}
class PublicKey {

    private MyBigInteger b;
    private MyBigInteger g;
    private MyBigInteger p;
    private MyBigInteger q;

    public PublicKey(MyBigInteger b, MyBigInteger g, MyBigInteger p, MyBigInteger q){
        this.b = b;
        this.g = g;
        this.p = p;
        this.q = q;
    }

    public void setB(MyBigInteger b){
        this.b = b;
    }

    public void setG(MyBigInteger g){
        this.g = g;
    }

    public void setP(MyBigInteger p){
        this.p = p;
    }

    public  void setQ(MyBigInteger q){ this. q = q;}

    public MyBigInteger getB(){
        return b;
    }

    public MyBigInteger getG(){
        return g;
    }

    public MyBigInteger getP(){
        return p;
    }
    public MyBigInteger getQ() { return q;}
}
class KeyGenerator {

    private PublicKey publicKey;
    private PrivateKey privateKey;

    public PublicKey getPublicKey(){
        return publicKey;
    }

    public PrivateKey getPrivateKey(){
        return privateKey;
    }

    public MyBigInteger generateG(MyBigInteger p, MyBigInteger q){
        MyBigInteger h = MyBigInteger.ONE.shiftLeft(159);
        MyBigInteger exp = p.subtract(MyBigInteger.ONE).divide(q);
        do {
            h = h.add(MyBigInteger.ONE);
        }while(h.modPow(exp, p).compareTo(MyBigInteger.ONE) <= 0);
        return  h.modPow(exp, p);

    }

    public MyBigInteger[] generatePAndQ(){

        RandomNumberGenerator random = new RandomNumberGenerator(System.currentTimeMillis());

        final int pSizeInBits = 1024;
        final int qSizeInBits = 160;
        MyBigInteger q = MyBigInteger.ONE;
        q = q.probablePrime(qSizeInBits, random);
        MyBigInteger k = MyBigInteger.ONE.shiftLeft(pSizeInBits - qSizeInBits); // k = 2**(pSizeInBits - qSizeInBits);

        MyBigInteger probablyPrime = q.multiply(k).add(MyBigInteger.ONE); // probablyPrime = q * k + 1
        while (!probablyPrime.isProbablePrime(4)) {
            q = q.probablePrime(qSizeInBits, random);
            probablyPrime = q.multiply(k).add(MyBigInteger.ONE);
        }

        MyBigInteger[] qAndP = new MyBigInteger[2];
        qAndP[0] = q;
        qAndP[1] = probablyPrime;

        return qAndP;
    }

    public void generateKey() {

        MyBigInteger a = new  MyBigInteger(160, new RandomNumberGenerator(System.currentTimeMillis()));
        MyBigInteger qAndp[] = generatePAndQ();
        MyBigInteger p = qAndp[1];
        MyBigInteger q = qAndp[0];
        MyBigInteger g = generateG(p, q);
        MyBigInteger b = g.modPow(a, p);

        publicKey = new PublicKey(b, g, p, q);
        privateKey = new PrivateKey(a);
		System.out.println(publicKey);
		System.out.println(privateKey);
    }

}
class PrivateKey {

    private MyBigInteger a;

    public PrivateKey(MyBigInteger a){
        this.a = a;

    }
    public void setA(MyBigInteger a){
        this.a = a;
    }

    public MyBigInteger getA(){
        return a;
    }

}
class SHA {

    public static String SHAHash(String str) {

        byte[] stringBytes = str.getBytes();

        int[] blocks = new int[(((stringBytes.length + 8) >> 6) + 1) * 16];

        int i;
        for(i = 0; i < stringBytes.length; i++) {
            blocks[i >> 2] |= stringBytes[i] << (24 - (i % 4) * 8);
        }

        blocks[i >> 2] |= 0x80 << (24 - (i % 4) * 8);
        blocks[blocks.length - 1] = stringBytes.length * 8; // na końcu długość wiadomości

        int[] w = new int[80];

        // Wartości początkowe:
        int h0 =  1732584193;
        int h1 = -271733879;
        int h2 = -1732584194;
        int h3 =  271733878;
        int h4 = -1009589776;

        // for (każda porcja)
        //   podziel porcję na 16 32-bitowych słów kodowanych big-endian w(i), 0 ≤ i ≤ 15
        for(i = 0; i < blocks.length; i += 16) {

           // Zainicjuj zmienne dla tej porcji:
            int a = h0;
            int b = h1;
            int c = h2;
            int d = h3;
            int e = h4;


            for(int j = 0; j < 80; j++) {

                // Rozszerz 16 32-bitowych słów w 80 32-bitowych słów:
                // for i from 16 to 79
                //  w(i) := (w(i-3) xor w(i-8) xor w(i-14) xor w(i-16)) <<< 1

                if(j < 16){
                    w[j] = blocks[i + j];
                }else{
                    w[j] = rot(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);
                }

                int k = 0;
                int f = 0;

                 if(j < 20){
                     f = ((b & c) | ((~b) & d));
                     k = 1518500249;
                 }else if(j < 40){
                     f = (b ^ c ^ d);
                     k = 1859775393;
                 }else if(j < 60){
                     f = ((b & c) | (b & d) | (c & d));
                     k = -1894007588;
                 }else if(j < 80){
                     f = (b ^ c ^ d);
                     k = -899497514;
                 }

                int temp = rot(a, 5) + e + w[j] + f + k;

                e = d;
                d = c;
                c = rot(b, 30);
                b = a;
                a = temp;
            }

            //Dodaj skrót tej porcji do dotychczasowego wyniku:
            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;
        }

        //skrót = h0 dopisz h1 dopisz h2 dopisz h3 dopisz h4
        int[] words = {h0,h1,h2,h3,h4};
        StringBuilder stringBuilder = new StringBuilder();

        //zamiana skrótu na stringa zapisanego w hexie
        for(int j = 0; j< words.length; j++)
        {
            String wordHex = Integer.toHexString(words[j]);

            while(wordHex.length() < 8){
                wordHex += '0';
            }

            stringBuilder.append(wordHex);
        }

        return stringBuilder.toString();
    }

    private static int rot(int number, int count) {
        return (number << count) | (number >>> (32 - count));
    }
}
class MyBigInteger implements Comparable<MyBigInteger> {

    private int[] digits;
    private int length;
    public static final MyBigInteger ZERO = MyBigInteger.valueOf("0");
    public static final MyBigInteger ONE = MyBigInteger.valueOf("1");
    public static final MyBigInteger TWO = MyBigInteger.valueOf("2");
    public static final MyBigInteger THREE = MyBigInteger.valueOf("3");

    public MyBigInteger(int numberOfBits, RandomNumberGenerator random) {
        byte[] byteArray;
        byteArray = fillByteArray(numberOfBits, random);
        digits = stripLeadingZeroBytes(byteArray);
        length = digits.length;
    }

    public MyBigInteger(String value, int radix) {
        this(new BigInteger(value, radix).toString());
    }


    private byte[] fillByteArray(int numBits, RandomNumberGenerator random) {

        int numBytes = (int) (((long) numBits + 7) / 8);
        byte[] randomBits = new byte[numBytes];

        if (numBytes > 0) {
            random.nextBytes(randomBits);
            int excessBits = 8 * numBytes - numBits;
            randomBits[0] &= (1 << (8 - excessBits)) - 1;
        }
        return randomBits;
    }

    private static int[] stripLeadingZeroBytes(byte a[]) {
        int byteLength = a.length;
        int keep;

        for (keep = 0; keep < byteLength && a[keep] == 0; keep++)
            ;

        int intLength = ((byteLength - keep) + 3) >>> 2;
        int[] result = new int[intLength];
        int b = byteLength - 1;
        for (int i = intLength - 1; i >= 0; i--) {
            result[i] = a[b--] & 0xff;
            int bytesRemaining = b - keep + 1;
            int bytesToTransfer = Math.min(3, bytesRemaining);
            for (int j = 8; j <= (bytesToTransfer << 3); j += 8)
                result[i] |= ((a[b--] & 0xff) << j);

            result[i] = Math.abs(result[i]);
        }
        return result;
    }

    public static MyBigInteger valueOf(String value) {
        return new MyBigInteger(value);
    }

    public MyBigInteger(int[] value) {
        length = value.length;
        digits = new int[length];

        for (int i = 0; i < length; i++) {
            digits[i] = value[i];
        }
    }

    public MyBigInteger(String value) {
        digits = new int[value.length()];
        length = value.length();
        setValue(value);
    }

    public void setValue(String value) {
        for (int i = value.length() - 1, j = length - 1; i >= 0; i--, j--) {
            digits[j] = Character.getNumericValue(value.charAt(i));
        }
    }

    public int[] getArrayValue() {
        return digits;
    }

    public int digitAt(int position) {
        return digits[position];
    }

    public int getNumberOfBits() {
        return length;
    }

    public MyBigInteger generateRandomNumber(RandomNumberGenerator random, int length, int[] array) {
        for (int i = 0; i < length; i++) {
            array[i] = random.random(9);
        }
        return new MyBigInteger(array);
    }

    public MyBigInteger add(MyBigInteger number) {
        if (number.length > length) {
            return number.add(this);
        } else {
            int[] result = new int[digits.length + 1];

            result[0] = 0;
            for (int i = 0; i < digits.length; i++) {
                result[i + 1] = digits[i];
            }
            for (int i = result.length - 1, j = number.getNumberOfBits() - 1; j >= 0; i--, j--) {
                result[i] += number.digitAt(j);
                if (result[i] > 9) {
                    result[i] = result[i] % 10;
                    result[i - 1] += 1;
                }
            }

            return new MyBigInteger(result);
        }
    }

    public MyBigInteger divide(MyBigInteger number) {
        int count = 0;
        BigInteger a = new BigInteger(this.toString());
        BigInteger b = new BigInteger(number.toString());

        // while (a.compareTo(b) >= 0) {
        a = a.subtract(b);
        count++;
        // }

        // ^ it works but it too slow .-.;
        BigInteger result = new BigInteger(this.toString()).divide(new BigInteger(number.toString()));
        return new MyBigInteger(result.toString());
    }

    public MyBigInteger reminder(MyBigInteger number) {
        BigInteger a = new BigInteger(this.toString());
        BigInteger b = new BigInteger(number.toString());

        //while (a.compareTo(b) >= 0) {
        a = a.subtract(b);
        // }

        BigInteger reminder = new BigInteger(this.toString()).remainder(new BigInteger(number.toString()));
        return new MyBigInteger(reminder.toString());
    }

    public MyBigInteger mod(MyBigInteger number) {
        return reminder(number);
    }

    public MyBigInteger multiply(MyBigInteger number) {
        if (number.compareTo(MyBigInteger.ZERO) == 0) {
            return new MyBigInteger(new BigInteger(this.toString()).multiply(new BigInteger(number.toString())).toString());
        } else if(number.equals(MyBigInteger.valueOf("-1"))){
            int n1 = length;
            int n2 = number.length;
            int[] result;
            if (number.length == this.length) {
                result = new int[length * number.length + 1];
                return new MyBigInteger((new BigInteger(toString()).multiply(new BigInteger(number.toString()))).toString());
            } else if (number.length > this.length) {
                return number.multiply(this);
            } else {
                result = new int[length * number.length];

                int i_n1 = 0;
                int i_n2 = 0;

                for (int i = n1 - 1; i >= 0; i--) {

                    int carry = 0;
                    int n11 = digits[i];
                    i_n2 = 0;

                    for (int j = n2 - 1; j >= 0; j--) {
                        int n22 = number.digits[j];
                        int sum = n11 * n22 + result[i_n1 + i_n2] + carry;
                        carry = sum / 10;
                        result[i_n1 + i_n2] = sum % 10;

                        i_n2++;
                    }
                    if (carry > 0)
                        result[i_n1 + i_n2] += carry;
                    i_n1++;
                }

                for (int i = 0; i < length * number.length / 2; i++) {
                    int temp = result[i];
                    result[i] = result[result.length - i - 1];
                    result[result.length - i - 1] = temp;
                }

                return new MyBigInteger(result);
            }
        }
        return new MyBigInteger(new BigInteger(this.toString()).multiply(new BigInteger(number.toString())).toString());
    }

    public MyBigInteger subtract(MyBigInteger number) {
        if (this.length < number.length) {
            return number.subtract(this);
        } else {
            int[] result = new int[digits.length];
            result[0] = 0;
            for (int i = 0; i < digits.length; i++) {
                result[i] = digits[i];
            }
            for (int i = length - 1, j = number.getNumberOfBits() - 1; j >= 0; i--, j--) {
                if (result[i] - number.digitAt(j) < 0) {
                    if (result[i - 1] == 0) {
                        result[i - 2] -= 1;
                        result[i - 1] += 9;
                    } else {
                        result[i - 1] -= 1;
                    }
                    result[i] += 10;
                }
                result[i] -= number.digitAt(j);
            }

            return new MyBigInteger(result);
        }

    }

    public MyBigInteger gcd(MyBigInteger number) {
        return gcdTwoNumbers(this, number);
    }

    private MyBigInteger gcdTwoNumbers(MyBigInteger a, MyBigInteger b) {
        if (b.compareTo(MyBigInteger.ZERO) == 0) return new MyBigInteger(a.toString());
        return gcdTwoNumbers(b, a.mod(b));
    }

    public MyBigInteger modPow(MyBigInteger number, MyBigInteger modulo) {
        return modPowTwoNumbers(new BigInteger(toString()), new BigInteger(number.toString()), new BigInteger(modulo.toString()));
        //return  modPowTwoNumbers(this, number, modulo);
    }

    private MyBigInteger modPowTwoNumbers(BigInteger x, BigInteger y, BigInteger p) {
        BigInteger res = BigInteger.ONE;
        x = x.mod(p);

        while (y.compareTo(BigInteger.ZERO) > 0) {
            if (y.mod(new BigInteger(""+2)).compareTo(BigInteger.ONE) == 0) {
                res = (res.multiply(x).mod(p));
            }
            y = y.shiftRight(1);
            x = x.multiply(x).mod(p);
        }
        return new MyBigInteger(res.toString());
    }

    public MyBigInteger modInverse(MyBigInteger number) {
        return modInverseTwoNumbers(this, number);
    }

    private MyBigInteger modInverseTwoNumbers(MyBigInteger a, MyBigInteger m) {
        if (a.gcd(m).compareTo(MyBigInteger.ONE) != 0) {
            throw new ArithmeticException("Inversion doesn't exist");
        }
        BigInteger m0 = new BigInteger(m.toString());
        BigInteger m1 = new BigInteger(m.toString());
        BigInteger a1 = new BigInteger(a.toString());
        BigInteger y = BigInteger.valueOf(0);
        BigInteger x = BigInteger.valueOf(1);

        if (m.compareTo(MyBigInteger.ONE) == 0)
            return MyBigInteger.ZERO;

        while (a1.compareTo(BigInteger.ONE) > 0) {
            BigInteger q = a1.divide(m1);
            BigInteger t = m1;

            m1 = a1.mod(m1);
            a1 = t;
            t = y;

            y = x.subtract(q.multiply(y));
            x = t;
        }

        if (x.compareTo(BigInteger.ZERO) < 0)
            x = x.add(m0);

        return new MyBigInteger(x.toString());
    }

    public boolean isProbablePrime(int k) { // Miller Rabin test
        BigInteger n = new BigInteger(this.toString());

        if (n.compareTo(BigInteger.ONE) == 0)
            return false;
        if (n.compareTo(BigInteger.valueOf(3)) < 0)
            return true;

        int s = 0;
        BigInteger d = n.subtract(BigInteger.ONE);
        while (d.mod(new BigInteger(""+2)).equals(BigInteger.ZERO)) {
            s++;
            d = d.divide(new BigInteger(""+2));
        }
        for (int i = 0; i < k; i++) {
            BigInteger a = uniformRandom(new BigInteger(""+2), n.subtract(BigInteger.ONE));
            BigInteger x = a.modPow(d, n);
            if (x.equals(BigInteger.ONE) || x.equals(n.subtract(BigInteger.ONE)))
                continue;
            int r = 0;
            for (; r < s; r++) {
                x = x.modPow(new BigInteger(""+2), n);
                if (x.equals(BigInteger.ONE))
                    return false;
                if (x.equals(n.subtract(BigInteger.ONE)))
                    break;
            }
            if (r == s)
                return false;
        }

        return true;
    }

    private BigInteger uniformRandom(BigInteger bottom, BigInteger top) {  // losowa liczba z zakresu (bottom, top)
        Random random = new Random();
        BigInteger res;

        do {
            res = new BigInteger(top.bitLength(), random);
        } while (res.compareTo(bottom) < 0 || res.compareTo(top) > 0);
        return res;
    }

    public MyBigInteger probablePrime(int bitLength, RandomNumberGenerator randomNumberGenerator) {
        MyBigInteger prime;
        do {

            do {
                prime = new MyBigInteger(bitLength, randomNumberGenerator);
            }
            while (prime.mod(MyBigInteger.TWO).compareTo(MyBigInteger.ZERO) == 0); // odrzucamy parzyste liczby bo wiadomo że nie są pierwsze

        } while (!prime.isProbablePrime(6));

        return new MyBigInteger(prime.toString());
    }
    public int bitLength() {
        return new BigInteger(this.toString()).bitLength();
    }

    public MyBigInteger and(MyBigInteger val) {
        int[] result = new int[Math.max(length, val.length)];
        for (int i = 0; i < result.length; i++)
            result[i] = digits[result.length - i - 1] & val.digits[result.length - i - 1];
        return new MyBigInteger(result);
    }

    public MyBigInteger shiftLeft(int n) {
        int a[] = digits;
        int len = length;
        int nInts = n >>> 5;
        int nBits = n & 0x1F;
        int bitsInHighWord = 32 - Integer.numberOfLeadingZeros(a[0]);

        // If shift can be done without recopy, do so
        if (n <= (32 - bitsInHighWord)) {
            primitiveLeftShift(a, len, nBits);
            return new MyBigInteger(new BigInteger(this.toString()).shiftLeft(n).toString());
        } else { // Array must be resized
            if (nBits <= (32 - bitsInHighWord)) {
                int result[] = new int[nInts + len];
                System.arraycopy(a, 0, result, 0, len);
                primitiveLeftShift(result, result.length, nBits);
                return new MyBigInteger(new BigInteger(this.toString()).shiftLeft(n).toString());
            } else {
                int result[] = new int[nInts + len + 1];
                System.arraycopy(a, 0, result, 0, len);
                primitiveRightShift(result, result.length, 32 - nBits);
                return new MyBigInteger(new BigInteger(this.toString()).shiftLeft(n).toString());
            }
        }

    }

    public MyBigInteger shiftRight(int n){
        BigInteger shifted = new BigInteger(this.toString());
        shifted = shifted.shiftRight(n);
        return new MyBigInteger(shifted.toString());
    }

    static void primitiveRightShift(int[] a, int len, int n) {
        int n2 = 32 - n;
        for (int i = len - 1, c = a[i]; i > 0; i--) {
            int b = c;
            c = a[i - 1];
            a[i] = (c << n2) | (b >>> n);
        }
        a[0] >>>= n;
    }

    // shifts a up to len left n bits assumes no leading zeros, 0<=n<32
    static void primitiveLeftShift(int[] a, int len, int n) {
        if (len == 0 || n == 0)
            return;

        int n2 = 32 - n;
        for (int i = 0, c = a[i], m = i + len - 1; i < m; i++) {
            int b = c;
            c = a[i + 1];
            a[i] = (b << n) | (c >>> n2);
        }
        a[len - 1] <<= n;
    }



    public int findBeginning() {
        int i = 0;
        do {
            i++;
        } while (i < length && digits[i] == 0);

        if (i == length) return 0;
        else
            return i - 1;
    }

    public String convertToString() {
        StringBuilder stringBuilder = new StringBuilder();

        for (int i = 0; i < digits.length; i++) {
            stringBuilder.append(Integer.toString(digits[i]));
        }
        return stringBuilder.toString();
    }

    @Override
    public int compareTo(MyBigInteger o) {
        if ((length - findBeginning()) > (o.length - o.findBeginning())) {
            return 1;
        } else if ((length - findBeginning()) < (o.length - o.findBeginning())) {
            return -1;
        } else if ((length - findBeginning()) == (o.length - o.findBeginning())) {
            boolean comparsion = false;
            int i = findBeginning();
            int j = o.findBeginning();

            do {
                comparsion = (digits[i] == o.digits[j]);
                i++;
                j++;
            } while (comparsion == true && i != getNumberOfBits() && j != o.getNumberOfBits());

            if (digits[i - 1] > o.digits[j - 1]) {
                return 1;
            } else if (digits[i - 1] < o.digits[j - 1]) {
                return -1;
            }
        }
        return 0;
    }

    @Override
    public String toString() {
        return convertToString();
    }

    @Override
    public boolean equals(Object x) {
        if (x == this)
            return true;

        if (!(x instanceof MyBigInteger))
            return false;

        MyBigInteger xInt = (MyBigInteger) x;

        if (this.length != xInt.length) {
            return false;
        }

        for (int i = 0; i < length; i++) {
            if (digits[i] != xInt.digits[i]) {
                return false;
            }
        }

        return true;
    }
}
class RandomNumberGenerator {

    private long last;
    private long next;

    public RandomNumberGenerator(long seed) {
        last = seed | 1;
        next = seed;
    }

    public int random(int max) {
        last ^= (last << 21);
        last ^= (last >>> 35);
        last ^= (last << 4);
        next += 123456789123456789L;
        int out = (int) ((last + next) % max);
        return Math.abs(out);
    }

    public int random() {
        last ^= (last << 21);
        last ^= (last >>> 35);
        last ^= (last << 4);
        next += 123456789123456789L;
        int out = (int) (last + next);
        return Math.abs(out);
    }

    public void nextBytes(byte[] bytes) {
        for (int i = 0; i < bytes.length; )
            for (int rnd = random(), n = Math.min(bytes.length - i, 4);
                 n-- > 0; rnd >>= 8)
                bytes[i++] = (byte) Math.abs(rnd);
    }

}