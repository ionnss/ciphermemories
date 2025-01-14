package handlers

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"os"
	"text/template"
)

// EmailData defines the expected structure for email template data
type EmailData struct {
	Title      string
	Message    string
	ButtonText string
	ButtonURL  string
}

func SendEmail(to, subject string, data *EmailData) error {
	// Validate parameters
	if to == "" || subject == "" || data == nil {
		return fmt.Errorf("invalid parameters")
	}

	// Get env variables
	from := os.Getenv("EMAIL_FROM_ADDRESS")
	fromName := os.Getenv("EMAIL_FROM_NAME")
	password := os.Getenv("SMTP_PASSWORD")
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")

	// Validate env variables
	if from == "" || password == "" || smtpHost == "" || smtpPort == "" {
		return fmt.Errorf("missing email configuration in env variables")
	}

	// Parse HTML template
	tmpl, err := template.ParseFiles("templates/emails/email.html")
	if err != nil {
		return fmt.Errorf("error parsing email template: %v", err)
	}

	// Execute the template
	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		return fmt.Errorf("error executing email template: %v", err)
	}

	// Create message with proper headers
	msg := []byte(fmt.Sprintf("From: %s <%s>\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/html; charset=\"utf-8\"\r\n"+
		"\r\n%s", fromName, from, to, subject, body.String()))

	// Configure TLS
	tlsConfig := &tls.Config{
		ServerName: smtpHost,
		MinVersion: tls.VersionTLS12,
	}

	// Create connection
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%s", smtpHost, smtpPort), tlsConfig)
	if err != nil {
		return fmt.Errorf("error connecting to SMTP server: %v", err)
	}
	defer conn.Close()

	// Create SMTP client
	client, err := smtp.NewClient(conn, smtpHost)
	if err != nil {
		return fmt.Errorf("error creating SMTP client: %v", err)
	}
	defer client.Close()

	// Authenticate
	auth := smtp.PlainAuth("", from, password, smtpHost)
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("error authenticating: %v", err)
	}

	// Set sender and recipient
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("error setting sender: %v", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("error setting recipient: %v", err)
	}

	// Send the email
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("error creating message writer: %v", err)
	}
	defer w.Close()

	_, err = w.Write(msg)
	if err != nil {
		return fmt.Errorf("error sending message: %v", err)
	}

	return nil
}

type EmailDataMemoriesManager struct {
	Title        string
	Message      string
	AttentionBox string
	Password     string
}

func MemoryManagerSendEmail(to, subject string, data *EmailDataMemoriesManager) error {
	// Validate parameters
	if to == "" || subject == "" || data == nil {
		return fmt.Errorf("invalid parameters")
	}

	// Get env variables
	from := os.Getenv("EMAIL_FROM_ADDRESS")
	fromName := os.Getenv("EMAIL_FROM_NAME")
	password := os.Getenv("SMTP_PASSWORD")
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")

	// Validate env variables
	if from == "" || password == "" || smtpHost == "" || smtpPort == "" {
		return fmt.Errorf("missing email configuration in env variables")
	}

	// Parse HTML template
	tmpl, err := template.ParseFiles("templates/emails/memory_manager_email.html")
	if err != nil {
		return fmt.Errorf("error parsing email template: %v", err)
	}

	// Execute the template
	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		return fmt.Errorf("error executing email template: %v", err)
	}

	// Create message with proper headers
	msg := []byte(fmt.Sprintf("From: %s <%s>\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/html; charset=\"utf-8\"\r\n"+
		"\r\n%s", fromName, from, to, subject, body.String()))

	// Configure TLS
	tlsConfig := &tls.Config{
		ServerName: smtpHost,
		MinVersion: tls.VersionTLS12,
	}

	// Create connection
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%s", smtpHost, smtpPort), tlsConfig)
	if err != nil {
		return fmt.Errorf("error connecting to SMTP server: %v", err)
	}
	defer conn.Close()

	// Create SMTP client
	client, err := smtp.NewClient(conn, smtpHost)
	if err != nil {
		return fmt.Errorf("error creating SMTP client: %v", err)
	}
	defer client.Close()

	// Authenticate
	auth := smtp.PlainAuth("", from, password, smtpHost)
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("error authenticating: %v", err)
	}

	// Set sender and recipient
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("error setting sender: %v", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("error setting recipient: %v", err)
	}

	// Send the email
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("error creating message writer: %v", err)
	}
	defer w.Close()

	_, err = w.Write(msg)
	if err != nil {
		return fmt.Errorf("error sending message: %v", err)
	}

	return nil
}
