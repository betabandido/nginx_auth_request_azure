package auth

import (
	"log"
	"net/http"
)

func HttpError(writer http.ResponseWriter, err error, message string, statusCode int) {
	logMessage := message
	if err != nil {
		logMessage += ": " + err.Error()
	}

	log.Print(logMessage)

	http.Error(writer, message, statusCode)
}
