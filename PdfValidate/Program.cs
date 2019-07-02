using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;

namespace PdfValidate
{
    class Program
    {
        static void Main(string[] args)
        {
            string pdfValidateUri = @"<FILE_PATH>";
            PdfReader reader = new PdfReader(pdfValidateUri);
            AcroFields fields = reader.AcroFields;
            List<String> names = fields.GetSignatureNames();

            foreach (string name in names)
            {
                Console.WriteLine("===== " + name + " =====");
                var pkcs7 = fields.VerifySignature(name);
                
                var signCert = pkcs7.Certificates[0];
                X509Certificate issuerCert = (pkcs7.Certificates.Length > 1 ? pkcs7.Certificates[1] : null);

                Console.WriteLine("=== Checking validity of the document today ===");
                CheckRevocation(pkcs7, signCert, issuerCert, DateTime.Now);
            }
            Console.ReadLine();

        }

        public static void CheckRevocation(PdfPKCS7 pkcs7, X509Certificate signCert, X509Certificate issuerCert, DateTime date)
        {
            List<BasicOcspResp> ocsps = new List<BasicOcspResp>();
            if (pkcs7.Ocsp != null)
                ocsps.Add(pkcs7.Ocsp);
            OcspVerifier ocspVerifier = new OcspVerifier(null, ocsps);
            List<VerificationOK> verification =
                ocspVerifier.Verify(signCert, issuerCert, date);
            if (verification.Count == 0)
            {
                List<X509Crl> crls = new List<X509Crl>();
                if (pkcs7.CRLs != null)
                    foreach (X509Crl crl in pkcs7.CRLs)
                        crls.Add(crl);
                CrlVerifier crlVerifier = new CrlVerifier(null, crls);
                verification.AddRange(crlVerifier.Verify(signCert, issuerCert, date));
            }
            if (verification.Count == 0)
                Console.WriteLine("The signing certificate couldn't be verified with the example");
            else
                foreach (VerificationOK v in verification)
                    Console.WriteLine(v);


            //Code not in the example, added by me
            //This way, I can find out if the certificate is revoked or not (through CRL). Not sure if it's the right way though
            if (verification.Count == 0 && pkcs7.CRLs != null && pkcs7.CRLs.Count != 0)
            {
                bool revoked = false;
                foreach (X509Crl crl in pkcs7.CRLs)
                {
                    revoked = crl.IsRevoked(pkcs7.SigningCertificate);
                    if (revoked)
                        break;
                }

                Console.WriteLine("Is certificate revoked?: " + revoked.ToString());
            }
        }

    }
}
