// javac -cp ".:bcprov-jdk18on-1.83.jar:xmlsec-4.0.4.jar" XMLEncryptionTest.java
//
// java -cp ".:bcprov-jdk18on-1.83.jar:xmlsec-4.0.4.jar" XMLEncryptionTest

import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

public class XMLEncryptionTest {
    static {
        // Initialize the Apache Santuario library
        org.apache.xml.security.Init.init();
    }

    public static void main(String[] args) throws Exception {
        // 1. Create a dummy XML Document
        String xmlString = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><bible translation=\"Korean Holy Bible (개역한글)\"><book name=\"Psalms\" id=\"PSA\"><chapter number=\"23\"><title>다윗의 시</title><verse number=\"1\">여호와는 나의 목자시니 내가 부족함이 없으리로다</verse><verse number=\"2\">그가 나를 푸른 초장에 누이시며 쉴만한 물 가으로 인도하시는도다</verse><verse number=\"3\">내 영혼을 소생시키시고 자기 이름을 위하여 의의 길로 인도하시는도다</verse><verse number=\"4\">내가 사망의 음침한 골짜기로 다닐지라도 해를 두려워하지 않을 것은 주께서 나와 함께 하심이라 주의 지팡이와 막대기가 나를 안위하시나이다</verse><verse number=\"5\">주께서 내 원수의 목전에서 내게 상을 베푸시고 기름으로 내 머리에 바르셨으니 내 잔이 넘치나이다</verse><verse number=\"6\">나의 평생에 선하심과 인자하심이 정녕 나를 따르리니 내가 여호와의 집에 영원히 거하리로다</verse></chapter></book></bible>";
        Document doc = DocumentBuilderFactory.newInstance()
                .newDocumentBuilder()
                .parse(new ByteArrayInputStream(xmlString.getBytes()));

        // 2. Generate a Secret Key (AES-128)
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey secretKey = keyGen.generateKey();

        // 3. Encrypt the <Secret> element
        Element root = doc.getDocumentElement();
        Element secretElement = (Element) root.getElementsByTagName("book").item(0);

        XMLCipher xmlCipher = XMLCipher.getInstance(XMLCipher.AES_128);
        xmlCipher.init(XMLCipher.ENCRYPT_MODE, secretKey);

        // This replaces the <Secret> element with <xenc:EncryptedData>
        doc = xmlCipher.doFinal(doc, secretElement);

        System.out.println("--- Encrypted XML ---");
        printDocument(doc);

        // 4. Decrypt
        XMLCipher xmlDecryptor = XMLCipher.getInstance(XMLCipher.AES_128);
        xmlDecryptor.init(XMLCipher.DECRYPT_MODE, secretKey);

        // Find the EncryptedData element
        Element encryptedDataElement = (Element) doc.getElementsByTagNameNS(
                "http://www.w3.org/2001/04/xmlenc#", "EncryptedData").item(0);

        doc = xmlDecryptor.doFinal(doc, encryptedDataElement);

        System.out.println("\n--- Decrypted XML ---");
        printDocument(doc);
    }

    private static void printDocument(Document doc) throws Exception {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();

        // Set properties for a clean, single-line output
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
        transformer.setOutputProperty(OutputKeys.INDENT, "no");

        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(doc), new StreamResult(writer));

        System.out.println(writer.toString());
    }
}