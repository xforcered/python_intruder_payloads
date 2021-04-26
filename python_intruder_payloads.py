from java.awt import GridBagLayout, GridBagConstraints, Font
from javax.swing import JScrollPane, JTextPane, JPanel, JButton, JFrame, JLabel, JTextArea
from javax.swing.text import SimpleAttributeSet
from java.awt.event import ActionListener, ActionEvent

from burp import IBurpExtender, IExtensionStateListener, IHttpListener, ITab, IIntruderPayloadGenerator
from burp import IIntruderPayloadGeneratorFactory, IIntruderPayloadProcessor

import base64
import traceback

_helpers, _callbacks = None, None

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory, IIntruderPayloadProcessor, IExtensionStateListener):

    #
    # implement IBurpExtender
    #
    
    def registerExtenderCallbacks(self, callbacks):
        # obtain an extension helpers object
        global _helpers, _callbacks
        _helpers = callbacks.getHelpers()
        _callbacks = callbacks

        # load scripts from file
        try:
            with open('generator_script.txt','r') as generator_script_fh:
                self._generator_script = generator_script_fh.read()
        except IOError:
            open('generator_script.txt','w').close()
        try:
            with open('processor_script.txt','r') as processor_script_fh:
                self._processor_script = processor_script_fh.read()
        except IOError:
            open('processor_script.txt','w').close()

        # set our extension name
        callbacks.setExtensionName("Python Payloads")

        # register ourselves as an Intruder payload generator
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        
        # register ourselves as an Intruder payload processor
        callbacks.registerIntruderPayloadProcessor(self)

        # register our UI tab
        self.python_payloads_tab = PythonPayloadsTab()
        self.python_payloads_tab.setGeneratorScript(self._generator_script)
        self.python_payloads_tab.setProcessorScript(self._processor_script)
        callbacks.customizeUiComponent(self.python_payloads_tab.getUiComponent())
        callbacks.addSuiteTab(self.python_payloads_tab)

        # register an extension state listener to save our scripts on extension unload
        callbacks.registerExtensionStateListener(self)


    #
    # implement IExtensionStateListener
    #

    def extensionUnloaded(self):
        global _callbacks
        try:
            with open('generator_script.txt','w') as generator_script_fh:
                generator_script_fh.write(self.python_payloads_tab.getGeneratorScript())
            with open('processor_script.txt','w') as processor_script_fh:
                processor_script_fh.write(self.python_payloads_tab.getProcessorScript())
        except Exception:
            traceback.print_exc(file=_callbacks.getStderr())
        return

    #
    # implement IIntruderPayloadGeneratorFactory
    #

    
    def getGeneratorName(self):
        return "Python Intruder Payloads"

    def createNewInstance(self, attack):
        # return a new IIntruderPayloadGenerator to generate payloads for this attack
        global _callbacks
        try:
            code = compile(self.python_payloads_tab.getGeneratorScript(), '<string>', 'exec')
        except Exception as e:
            traceback.print_exc(file=_callbacks.getStderr())
            return None

        return IntruderPayloadGenerator(code, attack)

    #
    # implement IIntruderPayloadProcessor
    #
    
    def getProcessorName(self):
        return "Python Intruder Payloads"

    def processPayload(self, currentPayload, originalPayload, baseValue):
        global _callbacks
        processor_script = self.python_payloads_tab.getProcessorScript()
        payload = None

        # TODO: pre-compile with a button in our custom JPane?
        try:
            processor_code = compile(processor_script, '<string>', 'exec')
        except Exception:
            traceback.print_exc(file=_callbacks.getStderr())
            return None

        try:
            base_value = _helpers.bytesToString(baseValue)
            current_payload = _helpers.bytesToString(currentPayload)
            original_payload = _helpers.bytesToString(originalPayload)
            exec(processor_code)
            return payload
        except Exception:
            traceback.print_exc(file=_callbacks.getStderr())
            return None



class PythonPayloadsTab(ITab):
    """ Implement ITab """
    def __init__(self):
        frame = JFrame()
        self.pane = frame.getContentPane()

        gridbag = GridBagLayout()
        self.pane.setLayout(gridbag)

        gridbag_constraints = GridBagConstraints()

        generator_label = JLabel('Intruder Payload Generator')

        # Align and add label to layout
        gridbag_constraints.fill = GridBagConstraints.HORIZONTAL
        gridbag_constraints.anchor = GridBagConstraints.CENTER
        gridbag_constraints.gridx = 0
        gridbag_constraints.gridy = 0
        gridbag_constraints.gridheight = 1
        gridbag_constraints.gridwidth = 3
        gridbag_constraints.weightx = .5
        gridbag_constraints.weighty = 0
        self.pane.add(generator_label, gridbag_constraints)

        # Create the generator script pane
        self.generator_script_pane = JTextPane()
        self.generator_script_pane.setFont(Font('Monospaced', Font.PLAIN, 11))
        self.generator_scroll_pane = JScrollPane()
        self.generator_scroll_pane.setViewportView(self.generator_script_pane)

        # Align and add the pane to the layout
        gridbag_constraints.fill = GridBagConstraints.BOTH
        gridbag_constraints.anchor = GridBagConstraints.CENTER
        gridbag_constraints.gridx = 0
        gridbag_constraints.gridy = 1
        gridbag_constraints.gridheight = 3
        gridbag_constraints.gridwidth = 3
        gridbag_constraints.weightx = 1
        gridbag_constraints.weighty = .9
        self.pane.add(self.generator_scroll_pane, gridbag_constraints)

        payload_processor_label = JLabel('Intruder Payload Processor')

        # Align and add label to layout
        gridbag_constraints.fill = GridBagConstraints.HORIZONTAL
        gridbag_constraints.anchor = GridBagConstraints.CENTER
        gridbag_constraints.gridx = 0
        gridbag_constraints.gridy = 4
        gridbag_constraints.gridheight = 1
        gridbag_constraints.gridwidth = 3
        gridbag_constraints.weightx = .5
        gridbag_constraints.weighty = 0
        self.pane.add(payload_processor_label, gridbag_constraints)

        # Create processor script pane
        self.processor_script_pane = JTextPane()
        self.processor_script_pane.setFont(Font('Monospaced', Font.PLAIN, 11))
        self.processor_scroll_pane = JScrollPane()
        self.processor_scroll_pane.setViewportView(self.processor_script_pane)

        # Align and add pane to layout
        gridbag_constraints.fill = GridBagConstraints.BOTH
        gridbag_constraints.anchor = GridBagConstraints.CENTER
        gridbag_constraints.gridx = 0
        gridbag_constraints.gridy = 5
        gridbag_constraints.gridheight = 3
        gridbag_constraints.gridwidth = 3
        gridbag_constraints.weightx = 1
        gridbag_constraints.weighty = .9
        self.pane.add(self.processor_scroll_pane, gridbag_constraints)

        # Create help label for payload generator
        payload_generator_help_text = 'Define a payload generator here.\n\n' \
                                      'Generated payloads should be in a list of\n' \
                                      'strings called "payloads".\n\n' \
                                      'For example, to generate numbers 0 - 9, you\n' \
                                      'could use the following script:\n\n' \
                                      'payloads = map(str,range(10))'
        payload_generator_help_label = JTextArea(payload_generator_help_text)
        payload_generator_help_label.setEditable(False)

        # Align and add label to layout
        gridbag_constraints.fill = GridBagConstraints.BOTH
        gridbag_constraints.anchor = GridBagConstraints.LINE_END
        gridbag_constraints.gridx = 3
        gridbag_constraints.gridy = 0
        gridbag_constraints.gridheight = 4
        gridbag_constraints.gridwidth = 1
        gridbag_constraints.weightx = 0
        gridbag_constraints.weighty = .9
        self.pane.add(payload_generator_help_label, gridbag_constraints)

        # Create help label for payload generator
        payload_processor_help_text = 'Define a payload processor here.\n\n' \
                                      'Burp Extender helper and callback functions are\n' \
                                      'available from _helpers and _callbacks, such as\n' \
                                      '_helpers.bytesToString(currentPayload)\n' \
                                      'The current payload is available in the\n' \
                                      'variable "current_payload".\n' \
                                      'The original pre-processed payload is available\n' \
                                      'in the variable "original_payload".\n' \
                                      'The original value at the inserted position\n' \
                                      'is available in the variable "base_value".\n' \
                                      'The processed payload should be placed in the\n' \
                                      'variable "payload" as a string.\n\n' \
                                      'For example, to reverse the payload, you could\n' \
                                      'use the following script:\n\n' \
                                      'payload = current_payload[::-1]'
        payload_processor_help_label = JTextArea(payload_processor_help_text)
        payload_processor_help_label.setEditable(False)

        # Align and add label to layout
        gridbag_constraints.fill = GridBagConstraints.BOTH
        gridbag_constraints.anchor = GridBagConstraints.LINE_END
        gridbag_constraints.gridx = 3
        gridbag_constraints.gridy = 4
        gridbag_constraints.gridheight = 4
        gridbag_constraints.gridwidth = 1
        gridbag_constraints.weightx = 0
        gridbag_constraints.weighty = .9
        self.pane.add(payload_processor_help_label, gridbag_constraints)


    def setProcessorScript(self, processor_script):
        if processor_script:
            self.processor_script_pane.document.insertString(self.processor_script_pane.document.length,
                                                             processor_script,
                                                             SimpleAttributeSet())

    def getProcessorScript(self):
        return self.processor_script_pane.document.getText(0,self.processor_script_pane.document.length)

    def setGeneratorScript(self, generator_script):
        if generator_script:
            self.generator_script_pane.document.insertString(self.generator_script_pane.document.length,
                                                             generator_script,
                                                             SimpleAttributeSet())

    def getGeneratorScript(self):
        return self.generator_script_pane.document.getText(0,self.generator_script_pane.document.length)

    def getTabCaption(self):
        return 'Python Payloads'

    def getUiComponent(self):
        return self.pane



#
# class to generate payloads from a simple list
#

class IntruderPayloadGenerator(IIntruderPayloadGenerator):
    def __init__(self, code, attack):
        global _helpers, _callbacks
        self._payloadIndex = 0
        payloads = []
        try:
            exec(code)
            self.payloads = payloads
        except Exception as e:
            traceback.print_exc(file=_callbacks.getStderr())

    def hasMorePayloads(self):
        return self._payloadIndex < len(self.payloads)

    def getNextPayload(self, baseValue):
        payload = self.payloads[self._payloadIndex]
        self._payloadIndex = self._payloadIndex + 1

        return payload

    def reset(self):
        self._payloadIndex = 0
