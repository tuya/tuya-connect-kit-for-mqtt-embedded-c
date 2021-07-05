#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qrencode.h"

static int casesensitive = 1;
static int eightbit = 0;
static int version = 0;
static int size = 1;
static int margin = 2;
static int micro = 0;
static QRecLevel level = QR_ECLEVEL_L;
static QRencodeMode hint = QR_MODE_8;

static QRcode *encode(const unsigned char *intext, int length)
{
	QRcode *code;

	if(micro) {
		if(eightbit) {
			code = QRcode_encodeDataMQR(length, intext, version, level);
		} else {
			code = QRcode_encodeStringMQR((char *)intext, version, level, hint, casesensitive);
		}
	} else if(eightbit) {
		code = QRcode_encodeData(length, intext, version, level);
	} else {
		code = QRcode_encodeString((char *)intext, version, level, hint, casesensitive);
	}

	return code;
}

static FILE *openFile(const char *outfile)
{
	FILE *fp;

	if(outfile == NULL || (outfile[0] == '-' && outfile[1] == '\0')) {
		fp = stdout;
	} else {
		fp = fopen(outfile, "wb");
		if(fp == NULL) {
			fprintf(stderr, "Failed to create file: %s\n", outfile);
			perror(NULL);
			exit(EXIT_FAILURE);
		}
	}

	return fp;
}

static void writeUTF8_margin(FILE* fp, int realwidth, const char* white,
                             const char *reset, const char* full)
{
	int x, y;

	for (y = 0; y < margin/2; y++) {
		fputs(white, fp);
		for (x = 0; x < realwidth; x++)
			fputs(full, fp);
		fputs(reset, fp);
		fputc('\n', fp);
	}
}

static int writeUTF8(const QRcode *qrcode, const char *outfile, int use_ansi, int invert)
{
	FILE *fp;
	int x, y;
	int realwidth;
	const char *white, *reset;
	const char *empty, *lowhalf, *uphalf, *full;

	empty = " ";
	lowhalf = "\342\226\204";
	uphalf = "\342\226\200";
	full = "\342\226\210";

	if (invert) {
		const char *tmp;

		tmp = empty;
		empty = full;
		full = tmp;

		tmp = lowhalf;
		lowhalf = uphalf;
		uphalf = tmp;
	}

	if (use_ansi){
		if (use_ansi == 2) {
			white = "\033[38;5;231m\033[48;5;16m";
		} else {
			white = "\033[40;37;1m";
		}
		reset = "\033[0m";
	} else {
		white = "";
		reset = "";
	}

	fp = openFile(outfile);

	realwidth = (qrcode->width + margin * 2);

	/* top margin */
	writeUTF8_margin(fp, realwidth, white, reset, full);

	/* data */
	for(y = 0; y < qrcode->width; y += 2) {
		unsigned char *row1, *row2;
		row1 = qrcode->data + y*qrcode->width;
		row2 = row1 + qrcode->width;

		fputs(white, fp);

		for (x = 0; x < margin; x++) {
			fputs(full, fp);
		}

		for (x = 0; x < qrcode->width; x++) {
			if(row1[x] & 1) {
				if(y < qrcode->width - 1 && row2[x] & 1) {
					fputs(empty, fp);
				} else {
					fputs(lowhalf, fp);
				}
			} else if(y < qrcode->width - 1 && row2[x] & 1) {
				fputs(uphalf, fp);
			} else {
				fputs(full, fp);
			}
		}

		for (x = 0; x < margin; x++)
			fputs(full, fp);

		fputs(reset, fp);
		fputc('\n', fp);
	}

	/* bottom margin */
	writeUTF8_margin(fp, realwidth, white, reset, full);

	// fclose(fp);

	return 0;
}

void example_qrcode_print(const char* productkey, const char* uuid)
{
	char buffer[255];
	printf("\r\n");
	sprintf(buffer, "https://smartapp.tuya.com/s/p?p=%s&uuid=%s&v=2.0", productkey, uuid);

    QRcode* qrcode = encode((const unsigned char*)buffer, sizeof(buffer));
    writeUTF8(qrcode, NULL, 0, 0);
}