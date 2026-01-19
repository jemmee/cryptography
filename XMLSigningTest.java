// javac -cp ".:bcprov-jdk18on-1.83.jar:xmlsec-4.0.4.jar" XMLSigningTest.java
//
// java -cp ".:bcprov-jdk18on-1.83.jar:xmlsec-4.0.4.jar" XMLSigningTest

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;

public class XMLSigningTest {
    static {
        // Initialize Santuario 4.0.4
        org.apache.xml.security.Init.init();
    }

    public static void main(String[] args) throws Exception {
        // 1. Create XML Document
        String xmlString = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><bible translation=\"Korean Holy Bible (개역한글)\"><book name=\"Psalms\" id=\"PSA\"><chapter number=\"23\"><title>다윗의 시</title><verse number=\"1\">여호와는 나의 목자시니 내가 부족함이 없으리로다</verse><verse number=\"2\">그가 나를 푸른 초장에 누이시며 쉴만한 물 가으로 인도하시는도다</verse><verse number=\"3\">내 영혼을 소생시키시고 자기 이름을 위하여 의의 길로 인도하시는도다</verse><verse number=\"4\">내가 사망의 음침한 골짜기로 다닐지라도 해를 두려워하지 않을 것은 주께서 나와 함께 하심이라 주의 지팡이와 막대기가 나를 안위하시나이다</verse><verse number=\"5\">주께서 내 원수의 목전에서 내게 상을 베푸시고 기름으로 내 머리에 바르셨으니 내 잔이 넘치나이다</verse><verse number=\"6\">나의 평생에 선하심과 인자하심이 정녕 나를 따르리니 내가 여호와의 집에 영원히 거하리로다</verse></chapter></book></bible>";
        Document doc = DocumentBuilderFactory.newInstance()
                .newDocumentBuilder()
                .parse(new ByteArrayInputStream(xmlString.getBytes()));

        // 2. Generate RSA Keys (Private for signing, Public for verification)
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        PrivateKey privateKey = kp.getPrivate();
        PublicKey publicKey = kp.getPublic();

        // 3. Create the Signature Object (Using RSA-SHA256)
        XMLSignature sig = new XMLSignature(doc, null, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);

        // Append the signature element to the document root
        doc.getDocumentElement().appendChild(sig.getElement());

        // 4. Add "Transforms" (Enveloped transform means the signature signs
        // the whole document EXCEPT itself)
        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        sig.addDocument("", transforms, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);

        // 5. Add KeyInfo (So the receiver knows which public key to use)
        sig.addKeyInfo(publicKey);

        // 6. Perform the Actual Signing
        sig.sign(privateKey);

        System.out.println("--- Signed XML ---");
        printDocument(doc);

        // --- 7. VERIFICATION (SUCCESS CASE) ---
        boolean isValid = verify(doc, publicKey);
        System.out.println("Initial Verification: " + (isValid ? "PASSED" : "FAILED"));

        // --- 8. TAMPER TEST (FAILURE CASE) ---
        System.out.println("\n[Action] Tampering with the Korean text...");
        // We change "나의" (my) to "너의" (your)
        doc.getElementsByTagName("title").item(0).setTextContent("솔로몬의 시");
        System.out.println("--- Tampered Signed XML ---");
        printDocument(doc);

        boolean isStillValid = verify(doc, publicKey);
        System.out.println("Verification after tampering: " + (isStillValid ? "PASSED" : "FAILED"));
    }

    private static boolean verify(Document doc, PublicKey publicKey) throws Exception {
        // Find the <ds:Signature> element
        NodeList nl = doc.getElementsByTagNameNS(Constants.SignatureSpecNS, "Signature");
        if (nl.getLength() == 0) {
            throw new Exception("No Signature found!");
        }
        Element sigElement = (Element) nl.item(0);

        // Reconstruct the XMLSignature object from the XML element
        XMLSignature signature = new XMLSignature(sigElement, "");

        // Check if the signature is cryptographically valid using the Public Key
        return signature.checkSignatureValue(publicKey);
    }

    private static void printDocument(Document doc) throws Exception {
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(doc), new StreamResult(writer));
        System.out.println(writer.toString());
    }
}