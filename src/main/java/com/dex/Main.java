package com.dex;

//import com.amazonaws.services.lambda.runtime.Context;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SNSEvent;
import org.json.JSONArray;
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
    private String subject = "";
    private String contentType = "";
    private JSONArray headers = new JSONArray();
    private JSONObject parsedSNS;
    private String spamVerdict;
    private String virusVerdict;
    private String spfVerdict;
    private String dkimVerdict;
    private String dmarcVerdict;
    boolean toForward;

    /*Keywords definition block*/
    /*Define subject keywords set*/
    HashSet<String> subjectKeywords = new HashSet<>();

    /*Lambda initialization*/
    public Main() {
        /*Keywords for subject filtering*/
        subjectKeywords.add("undeliverable");
//        subjectKeywords.add("automatique");
        subjectKeywords.add("not authori");
        subjectKeywords.add("invalid number");
//        subjectKeywords.add("out of office");
        subjectKeywords.add("automatic reply");
        subjectKeywords.add("error");
//        subjectKeywords.add("automatica");
//        subjectKeywords.add("automatische");
        subjectKeywords.add("not delivered");
//        subjectKeywords.add("autoreply");
        subjectKeywords.add("failure");


    }

    private void initialize(SNSEvent event) {
        parsedSNS = new JSONObject(event.getRecords().get(0).getSNS().getMessage());
        spamVerdict = parsedSNS.getJSONObject("receipt").getJSONObject("spamVerdict").getString("status");
        virusVerdict = parsedSNS.getJSONObject("receipt").getJSONObject("virusVerdict").getString("status");
        spfVerdict = parsedSNS.getJSONObject("receipt").getJSONObject("spfVerdict").getString("status");
        dkimVerdict = parsedSNS.getJSONObject("receipt").getJSONObject("dkimVerdict").getString("status");
        dmarcVerdict = parsedSNS.getJSONObject("receipt").getJSONObject("dmarcVerdict").getString("status");
//        subject = parsedSNS.getJSONObject("mail").getJSONObject("commonHeaders").getString("subject");
        headers = parsedSNS.getJSONObject("mail").getJSONArray("headers");
        for (int i = 0; i<headers.length(); i++){
            JSONObject header = headers.getJSONObject(i);
            String name = header.getString("name");
            String value = header.getString("value");
            switch (name){
                case "Content-Type":
                    contentType = value;
                    break;
                case "Subject":
                    subject = value;
                    break;
                case "From":
                    from = value;
                    break;

            }
        }

        toForward = subjectCheckToForward()
                && contentTypeCheckToForward();

        System.out.println(toForward);
    }
    /*End of Lambda initialization*/


    @Override
    public Context handleRequest(SNSEvent event, Context context) {

        try {
            initialize(event);
        } catch (Exception e) {
            System.out.println("ERROR: failure to initialize function");
            e.printStackTrace();
        }

            /*Check if message meet with forwarding criteria. Proceed with forwarding so*/
            if (toForward) {


//        System.out.println(event.toString());

                System.out.println(event.getRecords().get(0).getSNS().getMessage());

//        JSONObject parsedSNS = new JSONObject(event.getRecords().get(0).getSNS().getMessage());
                System.out.println(parsedSNS.getJSONObject("mail").getString("messageId"));
                String bucketName = parsedSNS.getJSONObject("receipt").getJSONObject("action").getString("bucketName");
                String objectKey = parsedSNS.getJSONObject("receipt").getJSONObject("action").getString("objectKey");


//                from = parsedSNS.getJSONObject("mail").getJSONObject("commonHeaders").getJSONArray("from").toList().get(0).toString();

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
                    if (emailContentBytes == null) {
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
                    if (toForward) {
                        forwardEmail(rawContent, from);
                    }
                } catch (Exception e) {
                    System.out.println("ERROR in handle request");
                    e.printStackTrace();
                }
            }

            return context;
        }

        private void forwardEmail (EmailContent emailContent, String from){

            HashSet<String> toEmail = new HashSet<>();    // Change this
//        toEmail.add("apikhtovnikov@dex.com");
//        toEmail.add("dexmailchecker-AWSSES@srv1.mail-tester.com");
            toEmail.add("jmark@dex.com");
            toEmail.add("apikhtovnikov@dex.com");
            SendEmailRequest request = SendEmailRequest.builder()
                    .content(emailContent)
                    .feedbackForwardingEmailAddress("aws_bounces@dex.com")
//                .replyToAddresses(from)
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

        private Part prependValidationResultsToPart (Part part, String validationResults) throws
        IOException, MessagingException {
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

                part.setContent(validationResults + content, "text/plain");

            } else if (part.isMimeType("text/html")) {
                System.out.println("We in text/html");
                String content = part.getContent().toString();
//            System.out.println(content);
                String htmpValidation = validationResults;
                htmpValidation = htmpValidation.replace("PASS", "<span style=\"color:green\">PASS</span>");
                htmpValidation = htmpValidation.replace("FAIL ", "<span style=\"color:red\">FAIL</span>");
                htmpValidation = htmpValidation.replace("GRAY", "<span style=\"color:orange\">GRAY</span>");
                htmpValidation = htmpValidation.replace("\r\n", "<br>");


                part.setContent(htmpValidation + content, "text/html");
            }

            return part;
        }

        private byte[] prependValidationResults (InputStream rawMessage, String validationResults){
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
            mimeMessage.setHeader("Reply-To", from);
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

        private boolean subjectCheckToForward () {

            for (String sbj : subjectKeywords
            ) {
                if (subject.toLowerCase().contains(sbj)) {
                    System.out.println("Subject: " + subject);
                    System.out.println("Hit: " + sbj);
                    return false;
                }
            }


            return true;
        }
        private boolean contentTypeCheckToForward () {
            if (contentType.toLowerCase().contains("report")){
                System.out.println("Subject: " + subject);
                System.out.println("Hit: " + contentType);
                return false;
            }
        return true;
        }
    }