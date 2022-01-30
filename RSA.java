package Controller;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {

    BigInteger p, q, n, totient, e, d;
    static String cipherteks;

    public static BigInteger GeneratePrime(int panjangbitprime) {
        //melakukan generate bilangan prima dengan panjang bit masukan user
        int N = panjangbitprime;
        SecureRandom random = new SecureRandom();
        BigInteger prime = BigInteger.probablePrime(N, random);
        return prime;
    }

    public static BigInteger hitungN(BigInteger p, BigInteger q) {
        //menghitung nilai n dengan mengalikan nilai prima p da q
        BigInteger n;
        n = p.multiply(q);

        return n;
    }

    public static BigInteger hitungtotient(BigInteger p, BigInteger q) {
        //menghitung nilai totient t= (p-1)*(q-1)
        BigInteger t;
        BigInteger p1 = new BigInteger("1");
        p = p.subtract(p1);
        q = q.subtract(p1);
        t = p.multiply(q);
        return t;
    }

    public static BigInteger gcd(BigInteger e, BigInteger totient) {
        //mencari fpb dari bilangan prima E dan totient
        //memilih nilai e [kunci publik] yang realtif prima dengan m [totient]
        BigInteger r, temp;
        BigInteger nol = new BigInteger("0");
        int compare = e.compareTo(totient);     //if  E<totient=-1

        if (compare == -1) {
            temp = e;
            e = totient;
            totient = temp;
        }
        while (totient.compareTo(nol) != 0) {
            r = e.mod(totient);
            e = totient;
            totient = r;
        }
        return e;
    }

    public static BigInteger hitung_pvt(BigInteger e, BigInteger totient) {

        // rumus awal e * d = 1 + k totient(n)
        //disederhanakan jadi d = 1+k(totient(n)) dibagi e
        //nilai k dicoba2
        BigInteger k, h, d;
        BigInteger satu = new BigInteger("1");
        k = new BigInteger("1");

        while (true) {
            d = k.multiply(e); //k*e
            h = d.mod(totient); //d mod totient

            if (h.compareTo(satu) == 0) {
                return k;
            } else {
                k = k.add(satu);

            }
        }
    }

    public static BigInteger[] atributRSA(String messagedigest, int panjangbitprime) {
        String md = messagedigest;
        BigInteger test;
        BigInteger satu = new BigInteger("1");
        BigInteger p = GeneratePrime(panjangbitprime);
        BigInteger q = GeneratePrime(panjangbitprime);
        System.out.println("P = " + p);
        System.out.println("Q = " + q);

        BigInteger nilaiN = hitungN(p, q);
        System.out.println("N = " + nilaiN);
        BigInteger totient = hitungtotient(p, q);
        System.out.println("totient = " + totient);
        BigInteger e;

        do {
            e = GeneratePrime(panjangbitprime);
            test = gcd(e, totient);
        } while (test.compareTo(satu) != 0);

        BigInteger d = hitung_pvt(e, totient);

        return new BigInteger[]{e, nilaiN, d};
    }

    public static pemecahanBlok[] pemisahanBlok(String messageDigest, BigInteger n) {

        String number = messageDigest;
        int panjangBlok = n.toString().length() - 1; //panjang blok digunakan unutk membagi blok sebelum dienkripsi
        int sisaBlok = number.length() % panjangBlok;
        int digitMax = n.toString().length();
        int panjangperulangan = (number.length() / panjangBlok);

        int panjangArray = (number.length() / panjangBlok);
        if (sisaBlok > 0) {
            panjangArray += 1;
        }
        pemecahanBlok[] chipertextBlok = new pemecahanBlok[panjangArray];

        int j = 0, i = 0, k = 0, l = 0;

        String tempBlok = "";
        int templength;

        while (k < panjangperulangan) {
            tempBlok = number.substring(i, i + panjangBlok);
            templength = tempBlok.length();
            pemecahanBlok digest = new pemecahanBlok(tempBlok, templength);
            chipertextBlok[k] = digest;
            i += panjangBlok;
            k++;
        }
        if (sisaBlok == 1) {
            tempBlok = number.substring(i);
            templength = tempBlok.length();
            pemecahanBlok digest = new pemecahanBlok(tempBlok, templength);
            chipertextBlok[k] = digest;
        } else if (sisaBlok >= 1) {
            tempBlok = number.substring(i, i + sisaBlok);
            templength = tempBlok.length();
            pemecahanBlok digest = new pemecahanBlok(tempBlok, templength);
            chipertextBlok[k] = digest;
        }

        System.out.println("panjang adt : " + chipertextBlok.length);
        System.out.println("panjang k : " + k);
        System.out.println("panjang : " + panjangArray);
        System.out.println("Hasil Pemisahan Blog ");
        for (i = 0; i < chipertextBlok.length; i++) {
            System.out.print(chipertextBlok[i].blok + " " + chipertextBlok[i].panjangBlok + "\t");
            // System.out.println("");
        }
        return chipertextBlok;
    }

    public static BigInteger[] enkripsi(pemecahanBlok blokPlaintext[], BigInteger n, BigInteger e) {

        BigInteger enkripsiValue[] = new BigInteger[blokPlaintext.length];

//      melakukan ekripsi setiap blok  
        BigInteger temp, temp2;
        String tempValue = "";
        System.out.println("\nHasil Enkripsi : ");

        for (int i = 0; i < blokPlaintext.length; i++) {
            temp = new BigInteger(blokPlaintext[i].blok);
            temp2 = temp.modPow(e, n);
            tempValue = temp2.toString();
            enkripsiValue[i] = new BigInteger(tempValue);
            System.out.print(enkripsiValue[i] + "\t");//System.out.println("");
        }
        return enkripsiValue;
    }

    public static String[] pemisahanBlokDes(String enkripsi) {

        String toDeskripsi = enkripsi;
        String[] blokQr = toDeskripsi.split("t", 0);

        for (String w : blokQr) {
            System.out.print(w + " ");
        }
        return blokQr;
    }

    public static String [] dekripsi(String blokChipertext[], BigInteger N, BigInteger d) {

        String [] dekripsi = new String [blokChipertext.length];
        BigInteger temp, temp2;
        String tempBlok = "";

        for (int i = 0; i < blokChipertext.length; i++) {
            temp = new BigInteger(blokChipertext[i]);
            temp2 = temp.modPow(d, N); //proses dekripsi
            tempBlok = temp2.toString();
            dekripsi[i] = tempBlok;
            System.out.print(dekripsi[i] + "\t");
            //System.out.println("");
        }

        return dekripsi;
    }

    public static String finalDekripsi(String fromDekripsi[], BigInteger N, int lastLength) {
        String finalDekripsi = "";
        int i;
        int tempL;
        int bitMax = N.toString().length() - 1;
        System.out.println("");

        for (i = 0; i < fromDekripsi.length - 1; i++) {
            if (fromDekripsi[i].length() != bitMax) {

                tempL = fromDekripsi[i].length();
                while (tempL < bitMax) {
                    fromDekripsi[i] = "0" + fromDekripsi[i];
                    tempL++;
                }
            }
            System.out.print(fromDekripsi[i] + "\t");
            finalDekripsi += fromDekripsi[i];
        }

        tempL = fromDekripsi[i].length();
        bitMax = lastLength;

        while (tempL < bitMax) {
            fromDekripsi[i] = "0" + fromDekripsi[i];
            tempL++;
        }
        finalDekripsi += fromDekripsi[i];
        System.out.println("\nhasil dekripsi  : " + finalDekripsi);

        return finalDekripsi;
    }

    /*
    public static void main(String[] args) {
//
////pembatas
        // TODO code application logic here
        String plaintext = "440472108104201000750662000497443800005502660112344566666789009";  //md5hash dalam desimal
        // String Chipertext = "1608577415250741428326323090315437924432394647125024748780178820212115205656";
        String plaintext3 = "40802";
        String Chipertext = "";
        int bitprima = 15;
        BigInteger plaintext2 = new BigInteger("1234");
        BigInteger N = new BigInteger("7169");
        BigInteger d = new BigInteger("883");
        BigInteger e = new BigInteger("103");

        BigInteger[] Signature = enkripsi(plaintext, bitprima);;
//        String temp123 = deksripsi(plaintext3, d, N);
//        System.out.println("hasi : " + temp123);


        /*
        P = 79
        Q = 127
        N = 10033
        totient = 9828
        Hasil Pemisahan Blog 
        4404 7210 8104 2010 7506 6249 7443 8055 0266 0112 3445 6666 6789 9900 9 
        6713 09567 06068 01741 03714 08080 01118 03518 06406 09258 04453 07934 00233 03571 03186 
        nilai : 67130956706068017410371408080011180351806406092580445307934002330357103186
        nilai e : 97
        nilai d : 2533
     */

}
