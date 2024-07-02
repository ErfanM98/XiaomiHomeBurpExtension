package burp;

import java.awt.Component;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BurpExtender implements IBurpExtender, IHttpListener, IMessageEditorTabFactory {

	
	private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    public PrintWriter pw;
     
	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		this.helpers = callbacks.getHelpers();
		this.callbacks.setExtensionName("Xiaomi Home RC4 decoder");
		
		this.pw = new PrintWriter(this.callbacks.getStdout(),true);
		pw.println("Hello burp");
		
		this.callbacks.registerHttpListener(this);
		this.callbacks.registerMessageEditorTabFactory(this);
		
		
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse message) {
		// TODO Auto-generated method stub
		
		
		
	}

	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		// TODO Auto-generated method stub
		
		return new XiaomiHomeTab(controller, editable,callbacks, this.pw) ;
	}

}

class XiaomiHomeTab implements IMessageEditorTab{
	
	
	private boolean editable;
    private ITextEditor txtInput;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
    public static String ssecurty = "qyv8sQlStTf+1QiFqpL7rg==";
    
    private PrintWriter pw;
    private String base64nonce;
    private Map<String,String> parameters;
    
    IMessageEditorController controller;
    
	public XiaomiHomeTab(IMessageEditorController controller, boolean editable, IBurpExtenderCallbacks callbacks, final PrintWriter pw) {
		pw.println("Constructor");
		this.editable = editable;
		this.callbacks = callbacks;
		this.controller = controller;
        // create an instance of Burp's text editor, to display our deserialized data
        this.txtInput = callbacks.createTextEditor();
        this.txtInput.setEditable(editable);

        helpers = callbacks.getHelpers();
        this.pw = pw;
        parameters = new HashMap<>();
        
        byte[] content = controller.getRequest();
        if (content == null) {
        	return;
        }
        
        IRequestInfo msg = helpers.analyzeRequest(content);
		
		String mainMessage = new String(Arrays.copyOfRange(content, msg.getBodyOffset(), content.length));
		
		mainMessage = helpers.urlDecode(mainMessage);
		
		txtInput.setText(mainMessage.getBytes());
		
		// split the message ;
		String[] parts = mainMessage.split("&");
		
		for (String part : parts) {
			String[] kv = part.split("=");
			parameters.put(kv[0], kv[1]);
		}
		
		
		
				
	}

	@Override
	public byte[] getMessage() {
		// TODO Auto-generated method stub
		byte[] b = {};
		return b;
	}

	@Override
	public byte[] getSelectedData() {
		// TODO Auto-generated method stub
		
		return txtInput.getSelectedText() ;
	}

	@Override
	public String getTabCaption() {
		return "Mi Home";
	}

	@Override
	public Component getUiComponent() {
		// TODO Auto-generated method stub
		return txtInput.getComponent();
	}
	
	private Map<String, String> getHeaders(List<String> rawHeaders){
		HashMap<String, String> headers = new HashMap<>();
		
		for(String item:rawHeaders){
			if (!item.contains(": ")){
				continue;
			}
			String[] kv = item.split(": ");
			headers.put(kv[0], kv[1]);
		  }
		return headers;
	}

	@Override
	public boolean isEnabled(byte[] content, boolean isRequest) {
		// TODO check if this is related to Xiaomi's web service
		
		if (!isRequest) {
			return isEnabled(controller.getRequest(), true);
			
		}
		
		Map<String, String> headers;
			IRequestInfo msg = helpers.analyzeRequest(content);
			headers = getHeaders(msg.getHeaders());
		
		if (!headers.containsKey("Host")) {
			return false;
		}
		if (!headers.get("Host").toLowerCase().contains(".mi.com")) {
			return false;
		}
		
		if (isRequest && !headers.containsKey("Miot-Encrypt-Algorithm")) {
			return false;
		}
		if (isRequest && headers.get("Miot-Encrypt-Algorithm").toLowerCase().equals("ENCRYPT-RC4".toLowerCase())) {
			return true;
		}
		
		return false;
	}

	@Override
	public boolean isModified() {
		return this.txtInput.isTextModified();
	}

	
	@Override
	public void setMessage(byte[] content, boolean isRequest) {

		if(!isRequest) {
			IResponseInfo res = helpers.analyzeResponse(content);
			String mainMessage = new String(Arrays.copyOfRange(content, res.getBodyOffset(), content.length));
		
			try {
				String result = RC4.decrypt(mainMessage, parameters.get("_nonce"), ssecurty);
				txtInput.setText(result.getBytes());
			} catch (Exception e) {
				txtInput.setText("Error occured while decrypting :)".getBytes());
			}
			return;
		}
		
		try {
			String result = RC4.decrypt(parameters.get("data"), parameters.get("_nonce"), ssecurty);
			txtInput.setText(result.getBytes());
		} catch (Exception e) {
			txtInput.setText("Error occured while decrypting :)".getBytes());
		}
		
		
	}
	
}
