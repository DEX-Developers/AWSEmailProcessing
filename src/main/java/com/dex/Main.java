package com.dex;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SNSEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONArray;
import org.json.JSONObject;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.sesv2.SesV2Client;
import software.amazon.awssdk.services.sesv2.model.EmailContent;
import software.amazon.awssdk.services.sesv2.model.SendEmailRequest;
import software.amazon.awssdk.services.sesv2.model.RawMessage;

import javax.mail.Part;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeMultipart;
import javax.mail.internet.MimeMessage;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.util.*;

import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;


/*Keys to form SQS message*/
enum sqsKeys {


    Category, ///*Possible Categories: Spam, Virus, Undeliverable, Unsubscribe, Autoanswer, HL*/
    S3ObjectLink,// link to email in S3
    From, //From
    Subject,
    MessageID, //Message ID that assign sender
    Date,
    InReplyTo //Message ID if email replied to our and this is potencial HL. Using our format
}

enum sqsCategories {
    Spam, Virus, ReportUndeliverable, ReportUnsubscribe, Unsubscribe, Autoanswer, HL, Other
}

public class Main implements RequestHandler<SNSEvent, String> {

    private static final String QUEUE_URL = "https://sqs.us-west-2.amazonaws.com/073628739062/AWSEmailProcSQS"; //SQS URL
    private static final String SPAM_QUEUE_URL = "https://sqs.us-west-2.amazonaws.com/073628739062/VirusesAndSpamAccounting"; // URL to send SPAMS
    private static final Region region = Region.US_WEST_2;
    /*Define global variables*/
    /*#######################*/
//    private final S3Client s3 = S3Client.create();
//    private final SesV2Client ses = SesV2Client.create();
//    private final String fromEmail = "jmark_processor@dex.com";  // Change this
    boolean toForward; //determine if we need to forward email to jmark or this is service email like undeliverables
    /*Keywords definition block*/
    /*Define subject keywords set*/
    HashSet<String> subjectUndeliverableKeywords = new HashSet<>();  //keywords in subject to parse message
    HashSet<String> subjectAutoanswerKeywords = new HashSet<>();  //keywords in subject to parse message
    private String bucketName;
    private String objectKey;
    private String from = "";
    private String subject = "";
    private String contentType = "";
    private String messageId = "";
    private String inReplyTo = "";
    private String dateParsed = "";
    private JSONArray headers = new JSONArray(); //for parsing headers
    private JSONObject parsedSNS; //original event that came from SNS
    private String spamVerdict;
    private String virusVerdict;
    private String spfVerdict;
    private String dkimVerdict;
    private String dmarcVerdict;
    private Map<String, String> sqsNotification = new HashMap<>();
    /*End of Global Variables definition*/
    /*##################################*/

    /*Lambda initialization*/
    private void initialize(SNSEvent event) {

        /*Parse SNS Event to extract Headers and Verdicts*/
        parsedSNS = new JSONObject(event.getRecords().get(0).getSNS().getMessage());
        spamVerdict = parsedSNS.getJSONObject("receipt").getJSONObject("spamVerdict").getString("status");
        virusVerdict = parsedSNS.getJSONObject("receipt").getJSONObject("virusVerdict").getString("status");
        spfVerdict = parsedSNS.getJSONObject("receipt").getJSONObject("spfVerdict").getString("status");
        dkimVerdict = parsedSNS.getJSONObject("receipt").getJSONObject("dkimVerdict").getString("status");
        dmarcVerdict = parsedSNS.getJSONObject("receipt").getJSONObject("dmarcVerdict").getString("status");
        headers = parsedSNS.getJSONObject("mail").getJSONArray("headers");
        bucketName = parsedSNS.getJSONObject("receipt").getJSONObject("action").getString("bucketName");
        objectKey = parsedSNS.getJSONObject("receipt").getJSONObject("action").getString("objectKey");
        /*End of SNS Event parsing*/

        /*Parse headers values*/
        for (int i = 0; i < headers.length(); i++) {
            JSONObject header = headers.getJSONObject(i);
            String name = header.getString("name").toLowerCase();
            String value = header.getString("value");
            switch (name) {
                case "content-type":
                    contentType = value;
                    break;
                case "subject":
                    subject = value;
                    break;
                case "from":
                    from = value;
                    break;
                case "message-id":
                    messageId = value;
                    break;
                case "in-reply-to":
                    inReplyTo = value;
                    break;
                case "date":
                    dateParsed = value;
                    break;
            }
        }
        /*End of parsing headers values*/

        /*Keywords for subject filtering - Autoanswers and Undeliverables*/
        subjectUndeliverableKeywords.add("undeliverable");
        subjectUndeliverableKeywords.add("not deliverable");
        subjectUndeliverableKeywords.add("unzustellbar");
        subjectUndeliverableKeywords.add("not authori");
        subjectUndeliverableKeywords.add("invalid number");
        subjectUndeliverableKeywords.add("error");
        subjectUndeliverableKeywords.add("not delivered");
        subjectUndeliverableKeywords.add("failure");
        subjectUndeliverableKeywords.add("failed");
        subjectUndeliverableKeywords.add("returned mail");
        subjectUndeliverableKeywords.add("non remis");
        subjectUndeliverableKeywords.add("ão entregue");
        subjectUndeliverableKeywords.add("mail returned");
        subjectUndeliverableKeywords.add("配信不能");
        subjectUndeliverableKeywords.add("배달되지 않음");
        subjectAutoanswerKeywords.add("automatique");
        subjectAutoanswerKeywords.add("自动答复");
        subjectAutoanswerKeywords.add("domain update");
        subjectAutoanswerKeywords.add("automática");
        subjectAutoanswerKeywords.add("out of office");
        subjectAutoanswerKeywords.add("automatic reply");
        subjectAutoanswerKeywords.add("automatica");
        subjectAutoanswerKeywords.add("automatische");
        subjectAutoanswerKeywords.add("autoreply");
        subjectAutoanswerKeywords.add("we have moved");
        /*End of subject keywords definition*/

        /*Determine if message must forward to jmark*/
        toForward = subjectCheckToForward()
                && contentTypeCheckToForward();
        System.out.println(toForward);
    }
    /*End of Lambda initialization*/

    /*Categorize email to send the report to SQS*/
    /*Working with HashMap 'sqsNotification' which contain email information*/
    private void sqsCategorize() {

        /*Fill out the sqsNotification template with determine categories and headers*/
        String category = getCategory();
        sqsNotification.put(sqsKeys.Category.name(), category);
        sqsNotification.put(sqsKeys.Date.name(), dateParsed);
        sqsNotification.put(sqsKeys.From.name(), from);
        sqsNotification.put(sqsKeys.Subject.name(), subject);
        sqsNotification.put(sqsKeys.InReplyTo.name(), inReplyTo);
        sqsNotification.put(sqsKeys.MessageID.name(), messageId);
        sqsNotification.put(sqsKeys.S3ObjectLink.name(), bucketName + "/" + objectKey);
        /*End of filling the sqsNotification*/

        /*Send SQS Notification to main SQS and, if spam or virus verticts is failed, to the SQS that account that events (two SQSs total)*/
        try (SqsClient sqsClient = SqsClient.builder().region(region).build()) {
//            System.out.println("Check SQS creation: " + new ObjectMapper().writeValueAsString(sqsNotification));
            sqsClient.sendMessage(SendMessageRequest.builder()
                    .queueUrl(QUEUE_URL)
                    .messageBody(new ObjectMapper().writeValueAsString(sqsNotification))
//                    .messageBody("Hello from AWS SDK for Java v2!")
                    .delaySeconds(10) // Optional parameter
                    .build());

            if (spamVerdict.toLowerCase().contains("fail") || virusVerdict.toLowerCase().contains("fail")) {
                sqsClient.sendMessage(SendMessageRequest.builder()
                        .queueUrl(SPAM_QUEUE_URL)
                        .messageBody(new ObjectMapper().writeValueAsString(sqsNotification))
                        .delaySeconds(10)
                        .build());
            }

            System.out.println("Messages sent successfully.");
        } catch (Exception e) {
            System.out.println("ERROR Failed to send message: ");
            e.printStackTrace();
        }

    }
    /*End of categorize email*/

    @Override
    public String handleRequest(SNSEvent event, Context context) {

        try {
            initialize(event);          //initialize variables
        } catch (Exception e) {
            System.out.println("ERROR: failure to initialize function");
            e.printStackTrace();
        }
        sqsCategorize();    //categorizing and sending SQSs

        /*Check if message meet with forwarding criteria. Proceed with forwarding so*/
        if (toForward) {


            System.out.println(event.getRecords().get(0).getSNS().getMessage());   // for debug. no functional load

            /*Prepare prepend string with verdicts to email body*/
            String prependVerdicts = new String("Spam: " + spamVerdict + " \r\n" +
                    "Virus: " + virusVerdict + " \r\n" +
                    "SPF: " + spfVerdict + " \r\n" +
                    "DKIM: " + dkimVerdict + " \r\n" +
                    "DMARC: " + dmarcVerdict + " \r\n" +
                    "====================================================================\r\n");
            /*End of verdicts string preparation*/

            GetObjectRequest getObjectRequest = GetObjectRequest.builder().bucket(bucketName).key(objectKey).build(); //define URL to extract from S3
            /*Extract Email from S3*/
            try (S3Client s3 = S3Client.create();
                    InputStream is = s3.getObject(getObjectRequest)) {
                // Fetch email content from S3
                byte[] emailContentBytes = prependValidationResults(is, prependVerdicts);  //call prepend function to add verdicts to the email body

                /*If for some reason function return null we reread the input stream*/
                if (emailContentBytes == null) {
                    emailContentBytes = is.readAllBytes();
                }
                SdkBytes rawInBytes = SdkBytes.fromByteArray(emailContentBytes);

                RawMessage rawMessage = RawMessage.builder()
                        .data(rawInBytes)
                        .build();

                EmailContent rawContent = EmailContent.builder()
                        .raw(rawMessage)
                        .build();

                /*Call email preparation and forwarding to jmark*/
                forwardEmail(rawContent);

            } catch (Exception e) {
                System.out.println("ERROR in handle request");
                e.printStackTrace();
            }
        }

        return "Email Proceed";
    }

    private void forwardEmail(EmailContent emailContent) {

        try (SesV2Client ses = SesV2Client.create()) {
            String fromEmail = "jmark_processor@dex.com";  // Change this
            HashSet<String> toEmail = new HashSet<>();    // List of recipients
//        toEmail.add("dexmailchecker-AWSSES@srv1.mail-tester.com");
            toEmail.add("jmark@dex.com");
            toEmail.add("apikhtovnikov@dex.com");

            /*Build up sending request*/
            SendEmailRequest request = SendEmailRequest.builder()
                    .content(emailContent)
                    .feedbackForwardingEmailAddress("aws_bounces@dex.com")
//                .replyToAddresses(from)
                    .fromEmailAddress(fromEmail)
                    .destination(d -> d.toAddresses(toEmail))
                    .build();
            System.out.println(request.toString());
            ses.sendEmail(request);
        } catch (Exception e){
            System.out.println("ERROR in forwardEmail method");
            e.printStackTrace();
        }
    }

    /*Check and prepend validation result if body part is text or html. Ignore in other cases*/
    private void prependValidationResultsToPart(Part part, String validationResults) throws
            IOException, MessagingException {
        System.out.println("Checking multipart");
        if (part.isMimeType("multipart/*")) {   //if multipart do RECURSION
            System.out.println("We in multipart 'if'");
            MimeMultipart multipart = (MimeMultipart) part.getContent();
            System.out.println(multipart.getCount());
            for (int i = 0; i < multipart.getCount(); i++) {
                prependValidationResultsToPart(multipart.getBodyPart(i), validationResults);  //Call the same function untill no multipart in the mimepart
            }
        } else if (part.isMimeType("text/plain")) {   //if plain text just add validation result to the content
            System.out.println("We in text/plain");
            String content = part.getContent().toString();

            part.setContent(validationResults + content, "text/plain");

        } else if (part.isMimeType("text/html")) {   //if mimepart html add contend and coloring them depends of status - fail,gray or pass
            System.out.println("We in text/html");
            String content = part.getContent().toString();
            String htmpValidation = validationResults;
            htmpValidation = htmpValidation.replace("PASS", "<span style=\"color:green\">PASS</span>");
            htmpValidation = htmpValidation.replace("FAIL ", "<span style=\"color:red\">FAIL</span>");
            htmpValidation = htmpValidation.replace("GRAY", "<span style=\"color:orange\">GRAY</span>");
            htmpValidation = htmpValidation.replace("\r\n", "<br>");


            part.setContent(htmpValidation + content, "text/html");
        }

    }

    /*Manupulate with email, parse mimepart and send it to recursive function to add validation result to all text or htmp part*/
    private byte[] prependValidationResults(InputStream rawMessage, String validationResults) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {   //output as try-with-resources
            Session session = Session.getDefaultInstance(new java.util.Properties());

            /*Manipulate with original headers*/
            MimeMessage mimeMessage = new MimeMessage(session, rawMessage);
            mimeMessage.setHeader("Return-Path", "aws_bounces@dex.com");
            mimeMessage.setSubject("[OrigFrom: " + from + " ] " + mimeMessage.getSubject());  //prepend subject with from content
            mimeMessage.setHeader("Reply-To", from);

            /*Call recursive function to parse all possible text and html parts of body*/
            prependValidationResultsToPart(mimeMessage, validationResults);
            mimeMessage.saveChanges();          //saving changes
            mimeMessage.writeTo(baos);             //write to output stream
            return baos.toByteArray();              //return output stream as byte array
        } catch (Exception e) {
            System.out.println("ERROR: Failed to parse raw message");
            e.printStackTrace();
        }

        System.out.println("No mime detected");
        return null;
    }

    /*Check is subject contain undeliverable words and set to do not forward key*/
    private boolean subjectCheckToForward() {

        for (String sbj : subjectUndeliverableKeywords
        ) {
            if (subject.toLowerCase().contains(sbj)) {
                System.out.println("Subject: " + subject);
                System.out.println("Hit: " + sbj);
                return false;
            }
        }
        return true;
    }

    /*check if it service message like report and set flag do not forward*/
    private boolean contentTypeCheckToForward() {
        if (contentType.toLowerCase().contains("report")) {
            System.out.println("Subject: " + subject);
            System.out.println("Hit: " + contentType);
            return false;
        }
        return true;
    }

    /*Categorize logic*/
    private String getCategory() {

        /*Block to get if email report unsubscribe or report undeliverable*/
        if (contentType.toLowerCase().contains("report")) {
            if (subject.toLowerCase().contains("unsubscribe")) {
                return sqsCategories.ReportUnsubscribe.name();
            } else {
                for (String sbj : subjectUndeliverableKeywords
                ) {
                    if (subject.toLowerCase().contains(sbj)) {
                        return sqsCategories.ReportUndeliverable.name();
                    }
                }
            }
        }

        /*Detect if email is autoanswer*/
        for (String sbj : subjectAutoanswerKeywords
        ) {
            if (subject.toLowerCase().contains(sbj)) {
                return sqsCategories.Autoanswer.name();
            }
        }

        /*Detect if it manual unsubscribe*/
        if (subject.toLowerCase().contains("unsubscribe")) {
            return sqsCategories.Unsubscribe.name();
        }

        /*Check if spam flag was set*/
        if (spamVerdict.toLowerCase().contains("fail")) {
            return sqsCategories.Spam.name();
        }

        /*Check if virus flag was set*/
        if (virusVerdict.toLowerCase().contains("fail")) {
            return sqsCategories.Virus.name();
        }

        /*If message contain RE: in the subgect it potential customer reply and hot lead. todo add more languages*/
        if (subject.toLowerCase().contains("re:")) {
            return sqsCategories.HL.name();
        }

        /*All other cases get mark other and need review carefully to exact the category and possible adding to this section*/
        return sqsCategories.Other.name();
    }
}