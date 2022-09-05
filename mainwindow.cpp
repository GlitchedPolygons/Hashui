#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include <mbedtls/md5.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

#include "lib/tiny_sha3/sha3.c"

static const uint8_t CRC8_TABLE[] = {
    //
    0x00, 0x5E, 0xBC, 0xE2, 0x61, 0x3F, 0xDD, 0x83, //
    0xC2, 0x9C, 0x7E, 0x20, 0xA3, 0xFD, 0x1F, 0x41, //
    0x9D, 0xC3, 0x21, 0x7F, 0xFC, 0xA2, 0x40, 0x1E, //
    0x5F, 0x01, 0xE3, 0xBD, 0x3E, 0x60, 0x82, 0xDC, //
    0x23, 0x7D, 0x9F, 0xC1, 0x42, 0x1C, 0xFE, 0xA0, //
    0xE1, 0xBF, 0x5D, 0x03, 0x80, 0xDE, 0x3C, 0x62, //
    0xBE, 0xE0, 0x02, 0x5C, 0xDF, 0x81, 0x63, 0x3D, //
    0x7C, 0x22, 0xC0, 0x9E, 0x1D, 0x43, 0xA1, 0xFF, //
    0x46, 0x18, 0xFA, 0xA4, 0x27, 0x79, 0x9B, 0xC5, //
    0x84, 0xDA, 0x38, 0x66, 0xE5, 0xBB, 0x59, 0x07, //
    0xDB, 0x85, 0x67, 0x39, 0xBA, 0xE4, 0x06, 0x58, //
    0x19, 0x47, 0xA5, 0xFB, 0x78, 0x26, 0xC4, 0x9A, //
    0x65, 0x3B, 0xD9, 0x87, 0x04, 0x5A, 0xB8, 0xE6, //
    0xA7, 0xF9, 0x1B, 0x45, 0xC6, 0x98, 0x7A, 0x24, //
    0xF8, 0xA6, 0x44, 0x1A, 0x99, 0xC7, 0x25, 0x7B, //
    0x3A, 0x64, 0x86, 0xD8, 0x5B, 0x05, 0xE7, 0xB9, //
    0x8C, 0xD2, 0x30, 0x6E, 0xED, 0xB3, 0x51, 0x0F, //
    0x4E, 0x10, 0xF2, 0xAC, 0x2F, 0x71, 0x93, 0xCD, //
    0x11, 0x4F, 0xAD, 0xF3, 0x70, 0x2E, 0xCC, 0x92, //
    0xD3, 0x8D, 0x6F, 0x31, 0xB2, 0xEC, 0x0E, 0x50, //
    0xAF, 0xF1, 0x13, 0x4D, 0xCE, 0x90, 0x72, 0x2C, //
    0x6D, 0x33, 0xD1, 0x8F, 0x0C, 0x52, 0xB0, 0xEE, //
    0x32, 0x6C, 0x8E, 0xD0, 0x53, 0x0D, 0xEF, 0xB1, //
    0xF0, 0xAE, 0x4C, 0x12, 0x91, 0xCF, 0x2D, 0x73, //
    0xCA, 0x94, 0x76, 0x28, 0xAB, 0xF5, 0x17, 0x49, //
    0x08, 0x56, 0xB4, 0xEA, 0x69, 0x37, 0xD5, 0x8B, //
    0x57, 0x09, 0xEB, 0xB5, 0x36, 0x68, 0x8A, 0xD4, //
    0x95, 0xCB, 0x29, 0x77, 0xF4, 0xAA, 0x48, 0x16, //
    0xE9, 0xB7, 0x55, 0x0B, 0x88, 0xD6, 0x34, 0x6A, //
    0x2B, 0x75, 0x97, 0xC9, 0x4A, 0x14, 0xF6, 0xA8, //
    0x74, 0x2A, 0xC8, 0x96, 0x15, 0x4B, 0xA9, 0xF7, //
    0xB6, 0xE8, 0x0A, 0x54, 0xD7, 0x89, 0x6B, 0x35, //
};

static inline uint8_t crc8(const uint8_t* data, const size_t length)
{
    assert(data != nullptr && length > 0 && "Tried to calculate CRC8 of a \"nullptr\" or empty (length = 0) data argument!");

    uint8_t crc = 0;

    for (size_t i = 0; i < length; ++i)
    {
        crc = CRC8_TABLE[crc ^ data[i]];
    }

    return crc;
}

static inline uint32_t crc32(const uint8_t* data, const size_t length)
{
    assert(data != nullptr && "Tried to calculate CRC32 of a \"nullptr\" data argument!");

    uint32_t crc = 0xFFFFFFFF;

    for (size_t i = 0; i < length; ++i)
    {
        crc ^= data[i];

        for (int ii = 8; ii; --ii)
        {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }

    return ~crc;
}

static inline uint32_t fnv1a(const uint8_t* data, const size_t dataLength)
{
    assert(sizeof(uint8_t) == sizeof(char));

    uint32_t hash = 2166136261;

    for (size_t i = 0; i < dataLength; ++i)
    {
        hash = 16777619 * (hash ^ data[i]);
    }

    return hash ^ (hash >> 16);
}

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_textEdit_textChanged()
{
    const QString text = this->ui->textEdit->toPlainText();
    const QString textLowercase = text.toLower();
    const QString textUppercase = text.toUpper();

    const QByteArray utf8 = text.toUtf8();
    const QByteArray utf8lowercase = textLowercase.toUtf8();
    const QByteArray utf8uppercase = textUppercase.toUtf8();

    const size_t utf8len = utf8.length();
    const uint8_t* utf8ptr = reinterpret_cast<const uint8_t*>(utf8.constData());

    const size_t utf8lowercaseLen = utf8lowercase.length();
    const uint8_t* utf8lowercasePtr = reinterpret_cast<const uint8_t*>(utf8lowercase.constData());

    const size_t utf8uppercaseLen = utf8uppercase.length();
    const uint8_t* utf8uppercasePtr = reinterpret_cast<const uint8_t*>(utf8uppercase.constData());

    const uint8_t r_crc8 = crc8(utf8ptr, utf8len);
    const uint32_t r_crc32 = crc32(utf8ptr, utf8len);
    const uint32_t r_fnv1a = fnv1a(utf8ptr, utf8len);

    const uint8_t r_crc8lowercase = crc8(utf8lowercasePtr, utf8lowercaseLen);
    const uint32_t r_crc32lowercase = crc32(utf8lowercasePtr, utf8lowercaseLen);
    const uint32_t r_fnv1alowercase = fnv1a(utf8lowercasePtr, utf8lowercaseLen);

    const uint8_t r_crc8uppercase = crc8(utf8uppercasePtr, utf8uppercaseLen);
    const uint32_t r_crc32uppercase = crc32(utf8uppercasePtr, utf8uppercaseLen);
    const uint32_t r_fnv1auppercase = fnv1a(utf8uppercasePtr, utf8uppercaseLen);

    uint8_t md5[16] = { 0x00 };
    uint8_t sha1[20] = { 0x00 };
    uint8_t sha256[32] = { 0x00 };
    uint8_t sha384[48] = { 0x00 };
    uint8_t sha512[64] = { 0x00 };
    uint8_t sha3_224[28] = { 0x00 };
    uint8_t sha3_256[32] = { 0x00 };
    uint8_t sha3_384[48] = { 0x00 };
    uint8_t sha3_512[64] = { 0x00 };

    uint8_t md5_lowercase[16] = { 0x00 };
    uint8_t sha1_lowercase[20] = { 0x00 };
    uint8_t sha256_lowercase[32] = { 0x00 };
    uint8_t sha384_lowercase[48] = { 0x00 };
    uint8_t sha512_lowercase[64] = { 0x00 };
    uint8_t sha3_224_lowercase[28] = { 0x00 };
    uint8_t sha3_256_lowercase[32] = { 0x00 };
    uint8_t sha3_384_lowercase[48] = { 0x00 };
    uint8_t sha3_512_lowercase[64] = { 0x00 };

    uint8_t md5_uppercase[16] = { 0x00 };
    uint8_t sha1_uppercase[20] = { 0x00 };
    uint8_t sha256_uppercase[32] = { 0x00 };
    uint8_t sha384_uppercase[48] = { 0x00 };
    uint8_t sha512_uppercase[64] = { 0x00 };
    uint8_t sha3_224_uppercase[28] = { 0x00 };
    uint8_t sha3_256_uppercase[32] = { 0x00 };
    uint8_t sha3_384_uppercase[48] = { 0x00 };
    uint8_t sha3_512_uppercase[64] = { 0x00 };

    mbedtls_md5(utf8ptr, utf8len, md5);
    mbedtls_sha1(utf8ptr, utf8len, sha1);
    mbedtls_sha256(utf8ptr, utf8len, sha256, 0);
    mbedtls_sha512(utf8ptr, utf8len, sha384, 1);
    mbedtls_sha512(utf8ptr, utf8len, sha512, 0);

    mbedtls_md5(utf8lowercasePtr, utf8lowercaseLen, md5_lowercase);
    mbedtls_sha1(utf8lowercasePtr, utf8lowercaseLen, sha1_lowercase);
    mbedtls_sha256(utf8lowercasePtr, utf8lowercaseLen, sha256_lowercase, 0);
    mbedtls_sha512(utf8lowercasePtr, utf8lowercaseLen, sha384_lowercase, 1);
    mbedtls_sha512(utf8lowercasePtr, utf8lowercaseLen, sha512_lowercase, 0);

    mbedtls_md5(utf8uppercasePtr, utf8uppercaseLen, md5_uppercase);
    mbedtls_sha1(utf8uppercasePtr, utf8uppercaseLen, sha1_uppercase);
    mbedtls_sha256(utf8uppercasePtr, utf8uppercaseLen, sha256_uppercase, 0);
    mbedtls_sha512(utf8uppercasePtr, utf8uppercaseLen, sha384_uppercase, 1);
    mbedtls_sha512(utf8uppercasePtr, utf8uppercaseLen, sha512_uppercase, 0);

    sha3(utf8ptr, utf8len, sha3_224, sizeof(sha3_224));
    sha3(utf8ptr, utf8len, sha3_256, sizeof(sha3_256));
    sha3(utf8ptr, utf8len, sha3_384, sizeof(sha3_384));
    sha3(utf8ptr, utf8len, sha3_512, sizeof(sha3_512));

    sha3(utf8lowercasePtr, utf8lowercaseLen, sha3_224_lowercase, sizeof(sha3_224_lowercase));
    sha3(utf8lowercasePtr, utf8lowercaseLen, sha3_256_lowercase, sizeof(sha3_256_lowercase));
    sha3(utf8lowercasePtr, utf8lowercaseLen, sha3_384_lowercase, sizeof(sha3_384_lowercase));
    sha3(utf8lowercasePtr, utf8lowercaseLen, sha3_512_lowercase, sizeof(sha3_512_lowercase));

    sha3(utf8uppercasePtr, utf8uppercaseLen, sha3_224_uppercase, sizeof(sha3_224_uppercase));
    sha3(utf8uppercasePtr, utf8uppercaseLen, sha3_256_uppercase, sizeof(sha3_256_uppercase));
    sha3(utf8uppercasePtr, utf8uppercaseLen, sha3_384_uppercase, sizeof(sha3_384_uppercase));
    sha3(utf8uppercasePtr, utf8uppercaseLen, sha3_512_uppercase, sizeof(sha3_512_uppercase));

    const QString decimalFormat("%1");

    this->ui->textEditLowercase->setText(textLowercase);
    this->ui->textEditUppercase->setText(textUppercase);

    this->ui->lineEditCRC8->setText(decimalFormat.arg(r_crc8));
    this->ui->lineEditCRC8_lowercase->setText(decimalFormat.arg(r_crc8lowercase));
    this->ui->lineEditCRC8_uppercase->setText(decimalFormat.arg(r_crc8uppercase));

    this->ui->lineEditCRC32->setText(decimalFormat.arg(r_crc32));
    this->ui->lineEditCRC32_lowercase->setText(decimalFormat.arg(r_crc32lowercase));
    this->ui->lineEditCRC32_uppercase->setText(decimalFormat.arg(r_crc32uppercase));

    this->ui->lineEditFNV1a->setText(decimalFormat.arg(r_fnv1a));
    this->ui->lineEditFNV1a_lowercase->setText(decimalFormat.arg(r_fnv1alowercase));
    this->ui->lineEditFNV1a_uppercase->setText(decimalFormat.arg(r_fnv1auppercase));

    this->ui->lineEditMD5->setText(QByteArray(reinterpret_cast<const char*>(md5), sizeof(md5)).toHex());
    this->ui->lineEditMD5_lowercase->setText(QByteArray(reinterpret_cast<const char*>(md5_lowercase), sizeof(md5_lowercase)).toHex());
    this->ui->lineEditMD5_uppercase->setText(QByteArray(reinterpret_cast<const char*>(md5_uppercase), sizeof(md5_uppercase)).toHex());

    this->ui->lineEditSHA1->setText(QByteArray(reinterpret_cast<const char*>(sha1), sizeof(sha1)).toHex());
    this->ui->lineEditSHA1_lowercase->setText(QByteArray(reinterpret_cast<const char*>(sha1_lowercase), sizeof(sha1_lowercase)).toHex());
    this->ui->lineEditSHA1_uppercase->setText(QByteArray(reinterpret_cast<const char*>(sha1_uppercase), sizeof(sha1_uppercase)).toHex());

    this->ui->lineEditSHA256->setText(QByteArray(reinterpret_cast<const char*>(sha256), sizeof(sha256)).toHex());
    this->ui->lineEditSHA256_lowercase->setText(QByteArray(reinterpret_cast<const char*>(sha256_lowercase), sizeof(sha256_lowercase)).toHex());
    this->ui->lineEditSHA256_uppercase->setText(QByteArray(reinterpret_cast<const char*>(sha256_uppercase), sizeof(sha256_uppercase)).toHex());

    this->ui->lineEditSHA384->setText(QByteArray(reinterpret_cast<const char*>(sha384), sizeof(sha384)).toHex());
    this->ui->lineEditSHA384_lowercase->setText(QByteArray(reinterpret_cast<const char*>(sha384_lowercase), sizeof(sha384_lowercase)).toHex());
    this->ui->lineEditSHA384_uppercase->setText(QByteArray(reinterpret_cast<const char*>(sha384_uppercase), sizeof(sha384_uppercase)).toHex());

    this->ui->lineEditSHA512->setText(QByteArray(reinterpret_cast<const char*>(sha512), sizeof(sha512)).toHex());
    this->ui->lineEditSHA512_lowercase->setText(QByteArray(reinterpret_cast<const char*>(sha512_lowercase), sizeof(sha512_lowercase)).toHex());
    this->ui->lineEditSHA512_uppercase->setText(QByteArray(reinterpret_cast<const char*>(sha512_uppercase), sizeof(sha512_uppercase)).toHex());

    this->ui->lineEditSHA3_224->setText(QByteArray(reinterpret_cast<const char*>(sha3_224), sizeof(sha3_224)).toHex());
    this->ui->lineEditSHA3_224_lowercase->setText(QByteArray(reinterpret_cast<const char*>(sha3_224_lowercase), sizeof(sha3_224_lowercase)).toHex());
    this->ui->lineEditSHA3_224_uppercase->setText(QByteArray(reinterpret_cast<const char*>(sha3_224_uppercase), sizeof(sha3_224_uppercase)).toHex());

    this->ui->lineEditSHA3_256->setText(QByteArray(reinterpret_cast<const char*>(sha3_256), sizeof(sha3_256)).toHex());
    this->ui->lineEditSHA3_256_lowercase->setText(QByteArray(reinterpret_cast<const char*>(sha3_256_lowercase), sizeof(sha3_256_lowercase)).toHex());
    this->ui->lineEditSHA3_256_uppercase->setText(QByteArray(reinterpret_cast<const char*>(sha3_256_uppercase), sizeof(sha3_256_uppercase)).toHex());

    this->ui->lineEditSHA3_384->setText(QByteArray(reinterpret_cast<const char*>(sha3_384), sizeof(sha3_384)).toHex());
    this->ui->lineEditSHA3_384_lowercase->setText(QByteArray(reinterpret_cast<const char*>(sha3_384_lowercase), sizeof(sha3_384_lowercase)).toHex());
    this->ui->lineEditSHA3_384_uppercase->setText(QByteArray(reinterpret_cast<const char*>(sha3_384_uppercase), sizeof(sha3_384_uppercase)).toHex());

    this->ui->lineEditSHA3_512->setText(QByteArray(reinterpret_cast<const char*>(sha3_512), sizeof(sha3_512)).toHex());
    this->ui->lineEditSHA3_512_lowercase->setText(QByteArray(reinterpret_cast<const char*>(sha3_512_lowercase), sizeof(sha3_512_lowercase)).toHex());
    this->ui->lineEditSHA3_512_uppercase->setText(QByteArray(reinterpret_cast<const char*>(sha3_512_uppercase), sizeof(sha3_512_uppercase)).toHex());
}
