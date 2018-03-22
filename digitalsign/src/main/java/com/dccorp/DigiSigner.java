package com.dccorp;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Container;
import java.awt.GridLayout;
import java.awt.Image;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
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
import java.util.Locale;
import java.util.ResourceBundle;

import javax.imageio.ImageIO;
import javax.swing.AbstractButton;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JRadioButton;
import javax.swing.border.Border;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.text.BaseColor;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Font;
import com.itextpdf.text.Font.FontFamily;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

/**
 * Main Class to sign pdfs via user digital certificates.
 * 
 * @author deepakchaudhary
 *
 */
public class DigiSigner extends JPanel implements ActionListener
{
	static final long serialVersionUID = 1L;

	/* progress bar to show progress. */
	static JProgressBar progressBar;
	/* location to download pdf, sign and prepare to upload. */
	static String _tempDirectory = System.getProperty(Constants.temp_directory);
	/* base URL to download pdf from remote server. */
	static String _baseURL = "";
	/* file name to be processed. passed via jnlp params. [f] */
	static String _fileNameToSign = Constants.emptyString;
	/*
	 * token for authenticatio purposes to get / post af ile. passed via jnlp param.
	 * [tk]
	 */
	static String _token = Constants.emptyString;
	/* signature count paramter from url. passed via knlp file params. [n] */
	static int _signCountParam = 1;
	/*
	 * default location to read file from. based on param passed via jnlp file. [t]
	 */
	static String _fileLocDwnldDef = Constants.fileLocDwnldDef;
	/*
	 * default location to read file from. based on param passed via jnlp file. [t]
	 */
	static String _fileLocDwnldTemp = Constants.fileLocDwnldTemp;
	static String _fileLoc = _fileLocDwnldDef;

	/* path of cert image to be displayed on UI. */
	static final String IMG_PATH = Constants.certsImgPath;

	/* keystore to read files from. */
	KeyStore keystore = null;
	char[] password = new char[]
	{ 'd' };

	/* button to start signing process. */
	protected JButton signPdfButton;

	/* Radio button group. */
	final ButtonGroup group;

	/* Resource bundle to read localized messages. */
	static ResourceBundle rb = null;

	/* Label to show messages during processing. */
	static JLabel msgLbl = new JLabel();
	static String msgLog = Constants.dots;

	static String _osName = "";

	/**
	 * Main method executed by jnlp languages_en_US.properties
	 * 
	 * @param args
	 */
	public static void main(String[] args)
	{
		// Locale locale = new Locale("pt", "PT");
		Locale locale = getDefaultLocale();
		rb = ResourceBundle.getBundle(Constants.rb_languages, locale);

		System.out.println(
				"languages_" + rb.getLocale().getLanguage() + "_" + rb.getLocale().getCountry() + ".properties");
		System.out.println("_tempDirectory: " + _tempDirectory);
		/* read url params */
		if (null != args && args.length > 0)
		{
			_signCountParam = Integer.valueOf(args[0]);

			// if (args[1].trim().equalsIgnoreCase("a"))
			// _fileLoc = _fileLocDwnldTemp;

			System.out.println("_fileLoc " + _fileLoc);

			_token = args[2];

			_fileNameToSign = args[3];

			// _baseURL = args[4] + "//" + args[5] + ":" + args[6] + args[7];
			_baseURL = args[4] + "://" + "escola.edulink.pt" + _fileLoc;

			/* launch applet */
			javax.swing.SwingUtilities.invokeLater(new Runnable()
			{
				public void run()
				{
					createAndShowGUI();
				}
			});
		} else
		{
			System.err.println(Constants.exitingMessage);
			System.exit(ERROR);
		}
	}

	/**
	 * constructor to initialize UI
	 */
	public DigiSigner()
	{
		super(new BorderLayout(20, 20));

		Border border = BorderFactory.createTitledBorder(rb.getString(Constants.rb_Select_Certificate));
		group = new ButtonGroup();
		JPanel radioPanel = new JPanel(new GridLayout(0, 1));
		radioPanel.setBorder(border);
		try
		{
			BufferedImage img = ImageIO.read(this.getClass().getResource(IMG_PATH));
			ImageIcon icon = new ImageIcon(img);
			Image image = icon.getImage(); // transform it
			Image newimg = image.getScaledInstance(30, 30, java.awt.Image.SCALE_SMOOTH); // scale it the smooth way
			icon = new ImageIcon(newimg); // transform it back
			_osName = System.getProperty("os.name").toLowerCase();
			if (_osName.indexOf(Constants._winOS) >= 0)
			{
				/* win keystore */
				System.out.println("loading windows keystore");
				keystore = KeyStore.getInstance(Constants.win_KeyChainStore, Constants.win_provider);
				keystore.load(null, null);
				password = null;
			} else
			{
				/* mac keystore */
				System.out.println("loading mac keystore");
				keystore = KeyStore.getInstance(Constants.mac_KeyChainStore, Constants.mac_provider);
				keystore.load(null, new char[0]);
			}

			for (Enumeration<String> oEnum = keystore.aliases(); oEnum.hasMoreElements();)
			{
				String sAlias = (String) oEnum.nextElement();
				System.out.println("@Alias: " + sAlias);
				X509Certificate oPublicCertificate = (X509Certificate) keystore.getCertificate(sAlias);
				System.out.println("Subject DN: " + oPublicCertificate.getSubjectDN());
				Key localKey = keystore.getKey(sAlias, password);
				System.out.println("@localKey: " + localKey);
				if (null != localKey)
				{
					System.out.println("localKey is not null " + localKey);
					if (isCertValid(oPublicCertificate))
					{
						System.out.println("cert was valid. Adding to gui now -->");
						/* add certs to UI for selection. */
						JRadioButton certAlias = new JRadioButton(oPublicCertificate.getSubjectDN().getName(), icon);
						certAlias.setOpaque(true);
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
			setMessage(e.getLocalizedMessage(), e.getClass().getName(), Color.RED);
		} catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
			setMessage(e.getLocalizedMessage(), e.getClass().getName(), Color.RED);
		} catch (CertificateException e)
		{
			e.printStackTrace();
			setMessage(e.getLocalizedMessage(), e.getClass().getName(), Color.RED);
		} catch (IOException e)
		{
			e.printStackTrace();
			setMessage(e.getLocalizedMessage(), e.getClass().getName(), Color.RED);
		} catch (UnrecoverableKeyException e)
		{
			e.printStackTrace();
			setMessage(e.getLocalizedMessage(), e.getClass().getName(), Color.RED);
		} catch (NoSuchProviderException e)
		{
			e.printStackTrace();
			setMessage(e.getLocalizedMessage(), e.getClass().getName(), Color.RED);
		}
		signPdfButton = new JButton(rb.getString(Constants.rb_Sign_PDF));
		signPdfButton.setFont(new java.awt.Font(null, Font.BOLD, 14));
		signPdfButton.setActionCommand(Constants.ac_downloadAndSign);
		signPdfButton.setEnabled(false);
		signPdfButton.setToolTipText(rb.getString(Constants.rb_ToolTipMsg));
		signPdfButton.setOpaque(true);
		/* button action listener to start signing process. */
		signPdfButton.addActionListener(new ActionListener()
		{
			/**
			 * 
			 */
			public void actionPerformed(java.awt.event.ActionEvent arg0)
			{
				System.out.println(group.getSelection().getActionCommand());
				try
				{
					progressBar.setValue(10);
					System.out.println(Constants.start_dwnld_msg);
					setMessage(rb.getString(Constants.start_dwnld_msg), Constants.emptyString, Color.BLUE);
					/* first download the file to temp directory */
					String respCode = downloadFile();
					if (!respCode.equalsIgnoreCase("1"))
						throw new Exception(respCode);
					System.out.println("respCode --> " + respCode);
					progressBar.setValue(30);
					System.out.println(Constants.dwnld_fshd);
					setMessage(rb.getString(Constants.dwnld_fshd), Constants.emptyString, Color.BLUE);
					/* prepare to sign the file */
					System.out.println(Constants.prep_sign);
					setMessage(rb.getString(Constants.prep_sign), "", Color.BLUE);
					signFilePrep(group.getSelection().getActionCommand());
					progressBar.setValue(80);
					/* upload the file to server */
					System.out.println(Constants.start_upload);
					setMessage(rb.getString(Constants.start_upload), Constants.emptyString, Color.BLUE);
					uploadFile();
					progressBar.setValue(100);
					System.out.println(Constants.proc_comp);
					setMessage(rb.getString(Constants.proc_comp), Constants.emptyString, Color.BLUE);
				} catch (GeneralSecurityException e)
				{
					e.printStackTrace();
					setMessage(e.getLocalizedMessage(), e.getClass().getName(), Color.RED);
				} catch (DocumentException e)
				{
					e.printStackTrace();
					setMessage(e.getLocalizedMessage(), e.getClass().getName(), Color.RED);
				} catch (IOException e)
				{
					// TODO Auto-generated catch block
					e.printStackTrace();
					setMessage(e.getLocalizedMessage(), e.getClass().getName(), Color.RED);
				} catch (Exception e)
				{
					// TODO Auto-generated catch block
					e.printStackTrace();
					setMessage(e.getLocalizedMessage(), e.getClass().getName(), Color.RED);
				}

			}
		});
		radioPanel.add(signPdfButton);
		add(radioPanel, BorderLayout.CENTER);
		setBorder(BorderFactory.createEmptyBorder(10, 50, 10, 40));
	}

	/**
	 * Used to set color of selected certificate on UI.
	 */
	public void actionPerformed(ActionEvent arg0)
	{
		System.out.println(arg0.getActionCommand());
		signPdfButton.setEnabled(true);
		JRadioButton source = (JRadioButton) arg0.getSource();
		for (Enumeration<AbstractButton> buttons = group.getElements(); buttons.hasMoreElements();)
		{
			AbstractButton b = buttons.nextElement();
			if (b != source)
			{
				/* reset to no color. */
				b.setBackground(null);

			} else
			{
				/* set to green color. */
				source.setBackground(Color.GREEN);
			}
		}
	}

	/**
	 * Create the GUI and show it. For thread safety, this method should be invoked
	 * from the event-dispatching thread.
	 */
	private static void createAndShowGUI()
	{
		/* Create and set up the window. */
		JFrame frame = new JFrame(rb.getString(Constants.rb_frameTitle));
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

		/* Create and set up the content pane. */
		JComponent newContentPane = new DigiSigner();
		newContentPane.setOpaque(true); // content panes must be opaque
		frame.setContentPane(newContentPane);

		Container content = frame.getContentPane();
		JPanel infoPanel = new JPanel(new GridLayout(0, 1));
		msgLbl.setText(msgLog);
		msgLbl.setFont(new java.awt.Font(null, Font.ITALIC, 12));
		msgLbl.setOpaque(true);
		msgLbl.setForeground(Color.BLUE);
		progressBar = new JProgressBar();
		progressBar.setValue(10);
		progressBar.setStringPainted(true);
		// progressBar.setBorder(border);
		Border border = BorderFactory.createTitledBorder(rb.getString(Constants.rb_Signing) + Constants.dots);
		infoPanel.setBorder(border);
		infoPanel.add(progressBar);
		infoPanel.add(msgLbl);
		content.add(infoPanel, BorderLayout.SOUTH);

		// show it
		// this.setLocationRelativeTo(null);
		// this.setVisible(true);

		frame.setResizable(false);
		frame.pack();
		frame.setVisible(true);
		frame.setLocationRelativeTo(null);
	}

	/**
	 * Intermediate Method to sign a file.
	 * 
	 * @param alias
	 * @throws GeneralSecurityException
	 * @throws DocumentException
	 * @throws IOException
	 */
	public void signFilePrep(String alias) throws GeneralSecurityException, DocumentException, IOException
	{
		try
		{
			String SRC = _tempDirectory + "/" + _fileNameToSign;
			String DEST = _tempDirectory + "/S_" + _fileNameToSign;
			Provider provider = keystore.getProvider();
			String _providerName = provider.getName();
			if (_osName.indexOf(Constants._macOS) >= 0)
			{
				/* for mac we need BC as security provider. */
				System.out.println("setting mac provider");
				BouncyCastleProvider bcProvider = new BouncyCastleProvider();
				Security.addProvider(bcProvider);
				_providerName = bcProvider.getName();
			}
			Certificate[] chain = keystore.getCertificateChain(alias);
			Key localKey = keystore.getKey(alias, password);
			System.out.println(_providerName);
			doSign(chain, (PrivateKey) localKey, PdfSignatureAppearance.CERTIFIED_FORM_FILLING, SRC,
					String.format(DEST, 1), DigestAlgorithms.SHA256, _providerName, CryptoStandard.CMS);
		} catch (KeyStoreException e)
		{
			e.printStackTrace();
			throw e;
		} catch (NoSuchProviderException e)
		{
			e.printStackTrace();
			throw e;
		} catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
			throw e;
		} catch (CertificateException e)
		{
			e.printStackTrace();
			throw e;
		} catch (IOException e)
		{
			e.printStackTrace();
			throw e;
		}
	}

	/**
	 * Real method to sign file.
	 * 
	 * @param chain
	 * @param pk
	 * @param level
	 * @param src
	 * @param dest
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
		ExternalSignature signature = new PrivateKeySignature(pk, digestAlgorithm, provider);
		MakeSignature.signDetached(appearance, digest, signature, chain, null, null, null, 0, subfilter);
	}

	/**
	 * Method to download file from server.
	 * 
	 * @return String
	 */
	public String downloadFile()
	{
		return (String) AccessController.doPrivileged(new PrivilegedAction<Object>()
		{
			public Object run()
			{
				try
				{
					URL finalURL = new URL(_baseURL + "" + _fileNameToSign + "?token=" + _token);

					System.out.println("finalURL: " + finalURL);
					URLConnection conn = finalURL.openConnection();
					conn.setUseCaches(false);
					conn.setRequestProperty(Constants.http_userAgentKey, Constants.http_userAgentVal);
					ReadableByteChannel rbc = Channels.newChannel(conn.getInputStream());
					File tempDir = new File(_tempDirectory);
					File pageOutput = new File(tempDir, _fileNameToSign);
					FileOutputStream fos = new FileOutputStream(pageOutput);
					fos.getChannel().transferFrom(rbc, 0, Long.MAX_VALUE);
					fos.close();
					rbc.close();

				} catch (MalformedURLException x)
				{
					x.printStackTrace();
					return x.getLocalizedMessage();
				} catch (IOException e)
				{
					return e.getLocalizedMessage();
				}
				return "1";
			}
		});
	}

	/**
	 * Mehtod to upload signed file to server.
	 * 
	 * @throws IOException
	 */
	public void uploadFile() throws IOException
	{
		String boundary = Long.toHexString(System.currentTimeMillis()); // Just generate some unique random value.
		URLConnection connection;
		try
		{
			connection = new URL("http://escola.edulink.pt/?v=1072&n=1&id=15&t=a&tk=5nLAeCFLMPyCMgfhvmtaledLFDPnX&u=1")
					.openConnection();
			connection.setDoOutput(true); // This sets request method to POST.
			connection.setRequestProperty(Constants.http_contentTypeKey, Constants.http_contentTypeVal + boundary);
			connection.setRequestProperty(Constants.http_filePdfKey, Constants.signedPdfPrefix + _fileNameToSign);
			File fileToUpload = new File(_tempDirectory + Constants.signedPdfPrefix + _fileNameToSign);
			System.out.println("uploading file --> " + fileToUpload.getAbsolutePath());
			@SuppressWarnings("resource")
			FileChannel in = new FileInputStream(fileToUpload).getChannel();
			WritableByteChannel out = Channels.newChannel(connection.getOutputStream());
			in.transferTo(0, fileToUpload.length(), out);
			in.close();
			out.close();

		} catch (IOException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw e;
		}

	}

	/**
	 * Method to check if certificate is expired.
	 * 
	 * @param oPublicCertificate
	 * @return boolean
	 */
	public static boolean isCertValid(X509Certificate oPublicCertificate)
	{
		System.out.println("checking if cert is valid -->");
		return oPublicCertificate.getNotAfter().after((new Date()));
	}

	public static void setMessage(String msg, String msgClass, Color msgColor)
	{
		msgLbl.setForeground(msgColor);
		msgLbl.setText(msg + ":" + msgClass);
	}

}
