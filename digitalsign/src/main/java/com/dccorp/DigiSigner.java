package com.dccorp;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import javax.swing.AbstractButton;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JRadioButton;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.text.BaseColor;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Font;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.Font.FontFamily;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;

/**
 * Main Class to sign pdfs via user digital certificates.
 * 
 * @author deepakchaudhary
 *
 */
public class DigiSigner extends JPanel implements ActionListener
{
	private static final long serialVersionUID = 1L;
	/* location to download pdf, sign and prepare to upload. */
	static String _tempDirectory = System.getProperty("java.io.tmpdir");
	/* base URL to download pdf from remote server. */
	static String baseURL = "";
	/* file name to be processed. */
	static String _fileNameToSign = "";

	KeyStore keystore = null;
	char[] password = new char[]
	{ 'd' };
	public static final String IMG = "src/main/resources/bgimg.jpg";

	protected JButton signPdfButton;

	/**
	 * Main method executed by jnlp
	 * 
	 * @param args
	 */
	public static void main(String[] args)
	{
		System.out.println("_tempDirectory: " + _tempDirectory);
		if (null != args && args.length > 0)
		{
			System.out.println("File to Sign: " + args[0]);
			_fileNameToSign = args[0];
			baseURL = args[1] + "//" + args[2] + ":" + args[3] + args[4];
		} else
		{
			System.err.println("Nothing to sign. Exiting");
			System.exit(ERROR);
		}
		javax.swing.SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				createAndShowGUI();
			}
		});
	}

	/**
	 * constructor to initialize UI
	 */
	public DigiSigner()
	{
		super(new BorderLayout());
		final ButtonGroup group = new ButtonGroup();
		JPanel radioPanel = new JPanel(new GridLayout(0, 1));
		try
		{
			/*
			 * Get instance of the keystore lets see if client is mac
			 */
			keystore = KeyStore.getInstance("KeyChainStore", "Apple");
			if (null == keystore)
			{
				/* try see if client is windows */
				keystore = KeyStore.getInstance("Windows-MY", "SunMSCAPI");
			}
			/* Loading the keystore */
			keystore.load(null, new char[0]);

			for (Enumeration<String> oEnum = keystore.aliases(); oEnum.hasMoreElements();)
			{
				String sAlias = (String) oEnum.nextElement();
				System.out.println("@Alias: " + sAlias);
				X509Certificate oPublicCertificate = (X509Certificate) keystore.getCertificate(sAlias);
				System.out.println("Subject DN: " + oPublicCertificate.getSubjectDN());
				Key localKey = keystore.getKey(sAlias, password);
				if (null != localKey)
				{
					if (isCertValid(oPublicCertificate))
					{
						JRadioButton certAlias = new JRadioButton(sAlias + " [" + oPublicCertificate.getNotBefore()
								+ " / " + oPublicCertificate.getNotAfter());
						certAlias.setActionCommand(sAlias);
						certAlias.setSelected(true);
						group.add(certAlias);
						certAlias.addActionListener(this);
						radioPanel.add(certAlias);
					}
				}
			}
		} catch (KeyStoreException e)
		{
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		} catch (CertificateException e)
		{
			e.printStackTrace();
		} catch (IOException e)
		{
			e.printStackTrace();
		} catch (UnrecoverableKeyException e)
		{
			e.printStackTrace();
		} catch (NoSuchProviderException e)
		{
			e.printStackTrace();
		}
		signPdfButton = new JButton("Sign PDF");
		signPdfButton.setVerticalTextPosition(AbstractButton.CENTER);
		signPdfButton.setHorizontalTextPosition(AbstractButton.LEADING);
		signPdfButton.setActionCommand("downloadAndSign");
		signPdfButton.addActionListener(new ActionListener()
		{
			public void actionPerformed(java.awt.event.ActionEvent arg0)
			{
				System.out.println(group.getSelection().getActionCommand());
				try
				{
					/* first download the file to temp directory */
					downloadFile();
					/* prepare to sign the file */
					signFilePrep(group.getSelection().getActionCommand());
					/* upload the file to server */

				} catch (GeneralSecurityException e)
				{
					e.printStackTrace();
				} catch (DocumentException e)
				{
					e.printStackTrace();
				}
			}
		});
		radioPanel.add(signPdfButton);
		add(radioPanel, BorderLayout.LINE_START);
		setBorder(BorderFactory.createEmptyBorder(10, 50, 10, 40));
	}

	/**
	 * 
	 */
	public void actionPerformed(ActionEvent arg0)
	{
		System.out.println(arg0.getActionCommand());
	}

	/**
	 * Create the GUI and show it. For thread safety, this method should be invoked
	 * from the event-dispatching thread.
	 */
	private static void createAndShowGUI()
	{
		/* Create and set up the window. */
		JFrame frame = new JFrame("Select your certificate:");
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

		/* Create and set up the content pane. */
		JComponent newContentPane = new DigiSigner();
		newContentPane.setOpaque(true); // content panes must be opaque
		frame.setContentPane(newContentPane);
		frame.setResizable(false);
		// Display the window.
		frame.pack();
		frame.setVisible(true);
	}

	/**
	 * Intermediate Method to sign a file.
	 * 
	 * @param alias
	 * @throws GeneralSecurityException
	 * @throws DocumentException
	 */
	public void signFilePrep(String alias) throws GeneralSecurityException, DocumentException
	{
		try
		{
			String SRC = _tempDirectory + "/" + _fileNameToSign;
			String DEST = _tempDirectory + "/S_" + _fileNameToSign;
			Provider provider = keystore.getProvider();
			Certificate[] chain = keystore.getCertificateChain(alias);
			Key localKey = keystore.getKey(alias, password);
			doSign(chain, (PrivateKey) localKey, PdfSignatureAppearance.CERTIFIED_FORM_FILLING, SRC,
					String.format(DEST, 1), DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CMS);
		} catch (KeyStoreException e)
		{
			e.printStackTrace();
		} catch (NoSuchProviderException e)
		{
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		} catch (CertificateException e)
		{
			e.printStackTrace();
		} catch (IOException e)
		{
			e.printStackTrace();
		}
	}

	/**
	 * Real method to sign file.
	 * 
	 * @param chain
	 * @param pk
	 * @param level
	 * @param src
	 * @param name
	 * @param dest
	 * @param rectangle
	 * @param digestAlgorithm
	 * @param provider
	 * @param subfilter
	 * @throws GeneralSecurityException
	 * @throws IOException
	 * @throws DocumentException
	 */
	public void doSign(Certificate[] chain, PrivateKey pk, int level, String src, String dest, String digestAlgorithm,
			String provider, CryptoStandard subfilter) throws GeneralSecurityException, IOException, DocumentException
	{
		float width = 108;
		float height = 32;
		float leftIndex = 0;
		float widthIndex = 0;
		BouncyCastleProvider bcProvider = new BouncyCastleProvider();
		Security.addProvider(bcProvider);
		PdfReader reader = new PdfReader(src);
		Rectangle cropBox = reader.getCropBox(1);
		Rectangle rectangle = new Rectangle(cropBox.getLeft(), cropBox.getTop(height), cropBox.getLeft(width),
				cropBox.getTop());
		AcroFields fields = reader.getAcroFields();
		List<String> signatureNames = fields.getSignatureNames();

		System.out.println("document have " + signatureNames.size() + " signatures.");

		for (@SuppressWarnings("unused")
		String signame : fields.getSignatureNames())
		{
			leftIndex = leftIndex + 110;
			widthIndex = widthIndex + width + 110;
			rectangle = new Rectangle(cropBox.getLeft() + leftIndex, cropBox.getTop(height),
					cropBox.getLeft(widthIndex), cropBox.getTop());
		}
		rectangle.setBorder(Rectangle.BOX);
		rectangle.setBorderColor(BaseColor.DARK_GRAY);
		rectangle.setBorderWidth(0.5f);
		FileOutputStream os = new FileOutputStream(dest);
		PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0', null, true);
		// Creating the appearance
		PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
		appearance.setVisibleSignature(rectangle, 1, null);
		appearance.setLayer2Font(new Font(FontFamily.TIMES_ROMAN, 6));
		// appearance.setRenderingMode(RenderingMode.GRAPHIC_AND_DESCRIPTION);
		// appearance.setSignatureGraphic(image);
		// appearance.setImage(Image.getInstance(DigiSigner.class.getResource("src/main/resources/bgimg.jpg")));
		// appearance.setImageScale(-3);
		/* if its 3rd signature, lets close pdf for further changes */
		if (signatureNames.size() == 2)
			appearance.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);
		// else
		// appearance.setCertificationLevel(level);
		// appearance.setCertificationLevel(level);
		// Creating the signature
		ExternalDigest digest = new BouncyCastleDigest();
		ExternalSignature signature = new PrivateKeySignature(pk, digestAlgorithm, bcProvider.getName());
		MakeSignature.signDetached(appearance, digest, signature, chain, null, null, null, 0, subfilter);
	}

	/**
	 * Method to download file from server.
	 * 
	 * @return
	 */
	public String downloadFile()
	{
		return (String) AccessController.doPrivileged(new PrivilegedAction<Object>()
		{
			public Object run()
			{
				try
				{
					URL finalURL = new URL(baseURL + _fileNameToSign);
					ReadableByteChannel rbc = Channels.newChannel(finalURL.openStream());
					File tempDir = new File(_tempDirectory);
					File pageOutput = new File(tempDir, _fileNameToSign);
					@SuppressWarnings("resource")
					FileOutputStream fos = new FileOutputStream(pageOutput);
					fos.getChannel().transferFrom(rbc, 0, 1 << 24);
					return "1";
				} catch (Exception x)
				{
					x.printStackTrace();
					return null;
				}
			}
		});
	}

	/**
	 * Mehtod to upload signed file to server.
	 * 
	 * @param baseURL
	 * @param _fileNameToUpload
	 * @param _tempDirectory
	 * @return
	 */
	public String uploadFile(String baseURL, String _fileNameToUpload, String _tempDirectory)
	{
		return "1";
	}

	/**
	 * Method to check if certificate is expired.
	 * 
	 * @param oPublicCertificate
	 * @return
	 */
	public static boolean isCertValid(X509Certificate oPublicCertificate)
	{
		return oPublicCertificate.getNotAfter().before((new Date()));
	}

}
