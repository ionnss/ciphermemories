package translations

import (
	"sync"

	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
)

var (
	bundle *i18n.Bundle
	once   sync.Once
)

// initBundle initializes the translation bundle once
func initBundle() {
	once.Do(func() {
		bundle = i18n.NewBundle(language.English)
		bundle.LoadMessageFile("translations/en.yml")
		bundle.LoadMessageFile("translations/pt-br.yml")
	})
}

// Translate is a function that translates ciphermemories webapp to eng or pt-br
//
// Receives:
// - messageID: string ID to translate
// - lang: language to translate to (en or pt-br)
//
// Returns:
// - translated string
func Translate(messageID string, lang string) string {
	// Initialize bundle if not initialized
	initBundle()

	// Create localizer for the specified language
	localizer := i18n.NewLocalizer(bundle, lang)

	// Get translation
	translation, err := localizer.Localize(&i18n.LocalizeConfig{
		MessageID: messageID,
	})

	if err != nil {
		// Return message ID if translation not found
		return messageID
	}

	return translation
}

// GetDefaultLanguage returns the default language based on Accept-Language header
//
// Receives:
// - acceptLanguage: Accept-Language header value
//
// Returns:
// - language code (en or pt-br)
func GetDefaultLanguage(acceptLanguage string) string {
	tags, _, err := language.ParseAcceptLanguage(acceptLanguage)
	if err != nil || len(tags) == 0 {
		return "en"
	}

	// Match against our supported languages
	matcher := language.NewMatcher([]language.Tag{
		language.English,
		language.BrazilianPortuguese,
	})

	tag, _ := language.MatchStrings(matcher, tags[0].String())

	if tag == language.BrazilianPortuguese {
		return "pt-br"
	}

	return "en"
}
