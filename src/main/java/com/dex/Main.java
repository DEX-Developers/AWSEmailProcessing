package com.dex;

//import com.amazonaws.services.lambda.runtime.Context;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SNSEvent;
import org.json.JSONObject;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.sesv2.SesV2Client;
import software.amazon.awssdk.services.sesv2.model.*;
import software.amazon.awssdk.services.sesv2.model.RawMessage;
import org.apache.commons.io.IOUtils;
import javax.mail.*;
import javax.mail.BodyPart;
import javax.mail.Header;
import javax.mail.Multipart;
import javax.mail.internet.*;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.Properties;

import org.apache.james.mime4j.message.DefaultMessageBuilder;
//import org.apache.james.mime4j.message;
//import com.amazonaws.services.simpleemailv2.model.RawMessage;
//import software.amazon.awssdk.services.sesv2.model.SendRawEmailRequest;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import java.nio.charset.StandardCharsets;
import java.util.*;

import static software.amazon.awssdk.core.SdkBytes.fromByteArray;

//import com.amazonaws.services.s3.AmazonS3;
//import com.amazonaws.services.s3.AmazonS3ClientBuilder;
//import com.amazonaws.services.simpleemail.AmazonSimpleEmailService;
//import com.amazonaws.services.simpleemail.AmazonSimpleEmailServiceClientBuilder;

//import java.util.stream.Collectors;

public class Main implements RequestHandler<SNSEvent, Context> {


    //    private AmazonS3 s3Client = AmazonS3ClientBuilder.standard().withRegion(REGION).build();
//    private AmazonSimpleEmailService sesClient = AmazonSimpleEmailServiceClientBuilder.standard().withRegion(REGION).build();
    private final Region myRegion = Region.of("us-west-2");  // replace with your bucket's region

    private final S3Client s3 = S3Client.create();
    private final SesV2Client ses = SesV2Client.create();
    private String fromEmail = "jmark_processor@dex.com";  // Change this
    private String from;

    @Override
    public Context handleRequest(SNSEvent event, Context context) {
        String spamVerdict;
        String virusVerdict;
        String spfVerdict;
        String dkimVerdict;
        String dmarcVerdict;



//        System.out.println(event.toString());

        System.out.println(event.getRecords().get(0).getSNS().getMessage());
        JSONObject parsedSNS = new JSONObject(event.getRecords().get(0).getSNS().getMessage());
        System.out.println(parsedSNS.getJSONObject("mail").getString("messageId"));
        String bucketName = parsedSNS.getJSONObject("receipt").getJSONObject("action").getString("bucketName");
        String objectKey = parsedSNS.getJSONObject("receipt").getJSONObject("action").getString("objectKey");

        spamVerdict = parsedSNS.getJSONObject("receipt").getJSONObject("spamVerdict").getString("status");
        virusVerdict = parsedSNS.getJSONObject("receipt").getJSONObject("virusVerdict").getString("status");
        spfVerdict = parsedSNS.getJSONObject("receipt").getJSONObject("spfVerdict").getString("status");
        dkimVerdict = parsedSNS.getJSONObject("receipt").getJSONObject("dkimVerdict").getString("status");
        dmarcVerdict = parsedSNS.getJSONObject("receipt").getJSONObject("dmarcVerdict").getString("status");

        from = parsedSNS.getJSONObject("mail").getJSONObject("commonHeaders").getJSONArray("from").toList().get(0).toString();

        String prependVerdicts = new String("Spam: " + spamVerdict + " \r\n" +
                "Virus: " + virusVerdict + " \r\n" +
                "SPF: " + spfVerdict + " \r\n" +
                "DKIM: " + dkimVerdict + " \r\n" +
                "DMARC: " + dmarcVerdict + " \r\n" +
                "====================================================================\r\n");

        try {
            // Fetch email content from S3
            GetObjectRequest getObjectRequest = GetObjectRequest.builder().bucket(bucketName).key(objectKey).build();
            InputStream is = s3.getObject(getObjectRequest);
            byte[] emailContentBytes = prependValidationResults(is, prependVerdicts);
            if (emailContentBytes == null){
                emailContentBytes = is.readAllBytes();
            }
//            System.out.println("After Validation: " + new String(emailContentBytes));
//            String emailContent = new String(emailContentBytes, StandardCharsets.UTF_8);

//            assert emailContentBytes != null;
            SdkBytes rawInBytes = SdkBytes.fromByteArray(emailContentBytes);

            RawMessage rawMessage = RawMessage.builder()
                    .data(rawInBytes)
                    .build();

            EmailContent rawContent = EmailContent.builder()
                    .raw(rawMessage)
                    .build();


            // Forward email using SES v2
//            forwardEmail(emailContent);
            forwardEmail(rawContent, from);

        } catch (Exception e) {
            System.out.println("ERROR in handle request");
            e.printStackTrace();
        }


        return context;
    }

    private void forwardEmail(EmailContent emailContent, String from) {

        HashSet<String> toEmail = new HashSet<>();    // Change this
//        toEmail.add("apikhtovnikov@dex.com");
//        toEmail.add("dexmailchecker-AWSSES@srv1.mail-tester.com");
        toEmail.add("jmark@dex.com");
        toEmail.add("apikhtovnikov@dex.com");
        SendEmailRequest request = SendEmailRequest.builder()
                .content(emailContent)
                .feedbackForwardingEmailAddress("aws_bounces@dex.com")
                .replyToAddresses(from)
                .fromEmailAddress(fromEmail)
                .destination(d -> d.toAddresses(toEmail))
                .build();
        System.out.println(request.toString());

//        System.out.println(request.toString());
//        System.out.println(request.fromEmailAddress() + request.replyToAddresses().toString());
        ses.sendEmail(request);
////        SendEmailRequest request = SendEmailRequest.builder()
////                .fromEmailAddress(fromEmail)
////                .
//////                .destination(toEmail)
////                .rawMessage(RawMessage.builder()
////                        .data(fromByteArray(emailContentBytes))
////                        .build())
////                .build();
////
////        ses.sendEmail(request);
//        SendEmailRequest request = SendEmailRequest.builder()
//                .destination(Destination.builder().toAddresses(toEmail).build())
//                .content(
//                        EmailContent.builder()
//                                .simple(
//                                        Message.builder()
//                                                .body(Body.builder()
//                                                        .text(Content.builder().charset("UTF-8").data(emailContent).build())
//                                                        .build())
//                                                .subject(Content.builder().charset("UTF-8").data("Forwarded Email").build())
//                                                .build()
//                                )
//                                .build()
//                )
//                .fromEmailAddress(fromEmail)
//                .build();
//
//        ses.sendEmail(request);
    }

    private Part prependValidationResultsToPart(Part part, String validationResults) throws IOException, MessagingException {
        System.out.println("Checking multipart");
        if (part.isMimeType("multipart/*")) {
            System.out.println("We in multipart 'if'");
            MimeMultipart multipart = (MimeMultipart) part.getContent();
            System.out.println(multipart.getCount());
            for (int i = 0; i < multipart.getCount(); i++) {
                prependValidationResultsToPart(multipart.getBodyPart(i), validationResults);
            }
        } else if (part.isMimeType("text/plain")) {
            System.out.println("We in text/plain");
            String content = part.getContent().toString();
//            System.out.println(content);

            part.setContent(validationResults + content,"text/plain");

        }else if (part.isMimeType("text/html")) {
            System.out.println("We in text/html");
            String content = part.getContent().toString();
//            System.out.println(content);
            String htmpValidation = validationResults;
            htmpValidation = htmpValidation.replace("PASS", "<span style=\"color:green\">PASS</span>");
            htmpValidation = htmpValidation.replace("FAIL ", "<span style=\"color:red\">FAIL</span>");
            htmpValidation = htmpValidation.replace("GRAY", "<span style=\"color:orange\">GRAY</span>");
            htmpValidation = htmpValidation.replace("\r\n", "<br>");


            part.setContent(htmpValidation + content,"text/html");}

        return part;
    }

    private byte[] prependValidationResults(InputStream rawMessage, String validationResults) {
        try {
            Session session = Session.getDefaultInstance(new java.util.Properties());
            MimeMessage mimeMessage = new MimeMessage(session, rawMessage);

//            Enumeration<Header> headers = mimeMessage.getAllHeaders();
//            while (headers.hasMoreElements()) {
//                Header header = headers.nextElement();
//                System.out.println(header.getName() + ": " + header.getValue());
//            }
//            mimeMessage.removeHeader("From");
//            mimeMessage.removeHeader("Received-SPF:");
//            mimeMessage.removeHeader("Authentication-Results");
            mimeMessage.setHeader("Return-Path", "aws_bounces@dex.com");
            mimeMessage.setSubject("[OrigFrom: " + from + " ] " + mimeMessage.getSubject());
//            mimeMessage.setHeader("From", fromEmail);

//            mimeMessage.removeHeader("To");
//            mimeMessage.setHeader("Reply-To", from);
//            mimeMessage.setHeader("To", "dexmailchecker-AWSSES@srv1.mail-tester.com");
//            System.out.println("FROM MIME " + mimeMessage.getHeader("From", null));

            prependValidationResultsToPart(mimeMessage, validationResults);
            mimeMessage.saveChanges();

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            mimeMessage.writeTo(baos);
            return baos.toByteArray();
        } catch (Exception e) {
            System.out.println("ERROR: Failed to parse raw message");
            e.printStackTrace();
        }

        System.out.println("No mime detected");
        return null;
    }

//    private void prependValidationResultsToEntity(Entity entity, String validationResults, BasicBodyFactory bodyFactory) throws IOException {
//        if (entity.isMultipart()) {
//            System.out.println("multipart detection");
//            Multipart multipart = (Multipart) entity.getBody();
//            for (Entity part : multipart.getBodyParts()) {
//                prependValidationResultsToEntity(part, validationResults, bodyFactory);
//            }
//        } else if (entity.getMimeType().startsWith("text/plain") || entity.getMimeType().startsWith("text/html")) {
//            System.out.println(entity.getMimeType());
//            TextBody originalBody = (TextBody) entity.getBody();
//            String originalText = IOUtils.toString(originalBody.getReader());
//            TextBody textBody = bodyFactory.textBody(validationResults + originalText, Charset.defaultCharset());
//            entity.removeBody();
//            entity.setBody(textBody);
//        }
//    }
//
//    private byte[] prependValidationResults(InputStream rawMessage, String validationResults) {
//        DefaultMessageBuilder messageBuilder = new DefaultMessageBuilder();
//
//        try {
//            Message mimeMessage = messageBuilder.parseMessage(rawMessage);
//            Header header = mimeMessage.getHeader();
////            Field fromField = header.getField("From");
//            HashMap<String, List<Field>> headersList = new HashMap<>(header.getFieldsAsMap());
//            for (Map.Entry<String, List<Field>> entry:
//                    headersList.entrySet()) {
//                System.out.println(entry.toString());
//            }
//
//            header.setField(DefaultFieldParser.parse(FieldName.FROM + ": " + fromEmail));
////            header.removeFields("From");
////            header.addField;
////            mimeMessage.setHeader("From", fromEmail);
//            System.out.println("FROM MIME " + mimeMessage.getFrom());
//
//
//            BasicBodyFactory bodyFactory = new BasicBodyFactory();
//
//            prependValidationResultsToEntity(mimeMessage, validationResults, bodyFactory);
//
//            ByteArrayOutputStream baos = new ByteArrayOutputStream();
//            MessageWriter meos = new DefaultMessageWriter();
//            meos.writeMessage(mimeMessage, baos);
//            return baos.toByteArray();
//        } catch (Exception e) {
//            System.out.println("ERROR: Failed to parse raw message");
//            e.printStackTrace();
//        }
//
//        System.out.println("No mime detected");
//        return null;
//    }


//    private byte[] prependValidationResults(InputStream rawMessage, String validationResults) {
//        DefaultMessageBuilder messageBuilder = new DefaultMessageBuilder();
//
//        try {
//            Message mimeMessage = messageBuilder.parseMessage(rawMessage);
//            String mimeType = mimeMessage.getMimeType();
//
//            BasicBodyFactory bodyFactory = new BasicBodyFactory();
//
//            if (mimeMessage.isMultipart()) {
//                Multipart multipart = (Multipart) mimeMessage.getBody();
//                System.out.println("Multipart detected: " + multipart.toString());
//
//                for (Entity part : mimeMultipartParser(multipart)) {
//                    System.out.println("We are in multipart cycle");
//                    System.out.println(part.getMimeType());
//                    if (part.getMimeType().equals("text/plain")|| part.getMimeType().equals("text/html")) {
//                        TextBody originalBody = (TextBody) part.getBody();
//                        String originalText = IOUtils.toString(originalBody.getReader());
//                        TextBody textBody = bodyFactory.textBody(validationResults + originalText, Charset.defaultCharset());
//                        part.setBody(textBody);
//                        System.out.println("We are in multipart cycle and if triggered");
//                    }
//                }
//            } else if (mimeType.startsWith("text/plain") || mimeType.startsWith("text/html")) {
//                System.out.println("Multipart not detected, but some mime detected");
//                TextBody originalBody = (TextBody) mimeMessage.getBody();
//                String originalText = IOUtils.toString(originalBody.getReader());
//                TextBody textBody = bodyFactory.textBody(validationResults + originalText, Charset.defaultCharset());
//                mimeMessage.setBody(textBody);
//            }
//
//            ByteArrayOutputStream baos = new ByteArrayOutputStream();
//            MessageWriter meos = new DefaultMessageWriter();
//            meos.writeMessage(mimeMessage, baos);
//            return baos.toByteArray();
//        } catch (Exception e) {
//            System.out.println("ERROR: Failed to parse raw message");
//            e.printStackTrace();
//            // Consider rethrowing the exception or returning a more meaningful error structure.
//        }
//        System.out.println("No mime detected");
//
//        return null;
//    }
//
//    private HashSet<Entity> mimeMultipartParser (Multipart multipart){
//        HashSet <Entity> result = new HashSet<Entity>();
//        for (Entity part : multipart.getBodyParts()) {
//            System.out.println("We are in multipart cycle");
//            System.out.println(part.getMimeType());
//            if (part.isMultipart()){
//                System.out.println("Another multipart");
//                result.addAll(Objects.requireNonNull(mimeMultipartParser((Multipart) part.getBody())));
//            }else result.add(part);
//
//        }
//        System.out.println(result.size());
//        return result;
//    }


//    private byte[] prependValidationResults(InputStream rawMessage, String validationResults) {
//        DefaultMessageBuilder messageBuilder = new DefaultMessageBuilder();
////        ByteArrayInputStream inputStream = new ByteArrayInputStream(rawMessage.getBytes(StandardCharsets.UTF_8));
//        try {
//            Message mimeMessage = messageBuilder.parseMessage(rawMessage);
//            // Check if the content type is text
//            String mimeType = mimeMessage.getMimeType();
//
//            BasicBodyFactory bodyFactory = new BasicBodyFactory();
//            if (mimeMessage.isMultipart()) {
//                Multipart multipart = (Multipart) mimeMessage.getBody();
//
//                for (Entity part : multipart.getBodyParts()) {
//                    String multiType = part.getMimeType();
//
//                    TextBody originalBody = (TextBody) part.getBody();
//                    String originalText = IOUtils.toString(originalBody.getReader());
//
//                    if (multiType.equals("text/plain")) {
//                        TextBody textBody = bodyFactory.textBody(validationResults + originalText, Charset.defaultCharset());
//                        part.setBody(textBody);
//                    } else if (multiType.equals("text/html")) {
//                        TextBody textBody = bodyFactory.textBody(validationResults + originalText, Charset.defaultCharset());
//                        part.setBody(textBody);
//                    }
//                }
//
//            }
//
//
//            else if  (mimeType.equals("text/plain") || mimeType.equals("text/html")) {
//                    TextBody originalBody = (TextBody) mimeMessage.getBody();
//                    String originalText = originalBody.getReader().toString();
//                    TextBody textBody = bodyFactory.textBody(validationResults + originalText, Charset.defaultCharset());
//                    mimeMessage.setBody(textBody);
//
//                }
//
//            ByteArrayOutputStream baos = new ByteArrayOutputStream();
//            MessageWriter meos = new DefaultMessageWriter();
//            meos.writeMessage(mimeMessage,baos);
//            return baos.toByteArray();
//        } catch (Exception e) {
//            System.out.println("ERROR: Failed to parse raw message");
//            e.printStackTrace();
//        }
//
//        return null;
//    }
}