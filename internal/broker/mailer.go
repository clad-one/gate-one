package broker

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
)

// Mailer sends account-lifecycle emails. The broker only needs the
// verification email in this slice; password reset will reuse it.
type Mailer interface {
	SendVerification(ctx context.Context, to, link string) error
}

type smtpMailer struct {
	cfg SMTPConfig
}

func newSMTPMailer(cfg SMTPConfig) Mailer {
	return &smtpMailer{cfg: cfg}
}

func (m *smtpMailer) SendVerification(
	_ context.Context, to, link string,
) error {
	from, err := mail.ParseAddress(m.cfg.From)
	if err != nil {
		return fmt.Errorf("smtp: invalid from address: %w", err)
	}

	const subject = "Verify your email address"
	body := "Bonjour,\r\n\r\n" +
		"Confirmez votre adresse e-mail en ouvrant ce lien :\r\n\r\n" +
		link + "\r\n\r\n" +
		"Si vous n'êtes pas à l'origine de cette demande, ignorez ce message.\r\n"

	msg := strings.Join([]string{
		"From: " + m.cfg.From,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"",
		body,
	}, "\r\n")

	addr := net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port))

	var client *smtp.Client
	if m.cfg.Port == 465 {
		conn, err := tls.Dial("tcp", addr, &tls.Config{
			ServerName: m.cfg.Host,
			MinVersion: tls.VersionTLS12,
		})
		if err != nil {
			return fmt.Errorf("smtp: dial: %w", err)
		}
		client, err = smtp.NewClient(conn, m.cfg.Host)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("smtp: client: %w", err)
		}
	} else {
		c, err := smtp.Dial(addr)
		if err != nil {
			return fmt.Errorf("smtp: dial: %w", err)
		}
		client = c
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{
				ServerName: m.cfg.Host,
				MinVersion: tls.VersionTLS12,
			}); err != nil {
				_ = client.Close()
				return fmt.Errorf("smtp: starttls: %w", err)
			}
		}
	}
	defer client.Close()

	if m.cfg.Username != "" {
		if err := client.Auth(smtp.PlainAuth(
			"", m.cfg.Username, m.cfg.Password, m.cfg.Host,
		)); err != nil {
			return fmt.Errorf("smtp: auth: %w", err)
		}
	}
	if err := client.Mail(from.Address); err != nil {
		return fmt.Errorf("smtp: mail from: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("smtp: rcpt to: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp: data: %w", err)
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		_ = w.Close()
		return fmt.Errorf("smtp: write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp: close data: %w", err)
	}
	return client.Quit()
}
