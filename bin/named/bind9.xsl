<!--
 - Copyright (C) 2006  Internet Systems Consortium, Inc. ("ISC")
 -
 - Permission to use, copy, modify, and distribute this software for any
 - purpose with or without fee is hereby granted, provided that the above
 - copyright notice and this permission notice appear in all copies.
 -
 - THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 - REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 - AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 - INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 - LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 - OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 - PERFORMANCE OF THIS SOFTWARE.
-->

<!-- $Id: bind9.xsl,v 1.5 2006/12/22 01:59:43 marka Exp $ -->

<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
   xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
   xmlns="http://www.w3.org/1999/xhtml">
  <xsl:template match="isc/bind/statistics">
    <html>
      <head>
        <style type="text/css">
body {
	font-family: sans-serif;
	background-color: #ffffff;
	color: #000000;
}

table {
	border-collapse: collapse;
}

tr.rowh {
	text-align: center;
	border: 1px solid #000000;
	background-color: #8080ff;
	color: #ffffff;
}

tr.row {
	text-align: right;
	border: 1px solid #000000;
	background-color: teal;
	color: #ffffff;
}

tr.lrow {
	text-align: left;
	border: 1px solid #000000;
	background-color: teal;
	color: #ffffff;
}

.header {
	background-color: teal;
	color: #ffffff;
	padding: 4px;
}

.content {
	background-color: #ffffff;
	color: #000000;
	padding: 4px;
}

.item {
	padding: 4px;
	align: right;
}

.value {
	padding: 4px;
	font-weight: bold;
}
        </style>
        <title>BIND 9 Statistics</title>
      </head>
      <body>
        <div class="header">Bind 9 Configuration and Statistics</div>

	<br/>

	<table>
	  <tr class="rowh"><th colspan="2">Times</th></tr>
	  <tr class="lrow">
	    <td>boot-time</td>
	    <td><xsl:value-of select="server/boot-time"/></td>
	  </tr>
	  <tr class="lrow">
	    <td>current-time</td>
	    <td><xsl:value-of select="server/current-time"/></td>
	  </tr>
	</table>

	<br/>

	<table>
	  <tr class="rowh"><th colspan="2">Server statistics</th></tr>
	  <xsl:for-each select="server/counters/*">
	    <tr class="lrow">
	      <td><xsl:value-of select="name()"/></td>
	      <td><xsl:value-of select="."/></td>
	    </tr>
	  </xsl:for-each>
	</table>

	<br />	

	<xsl:for-each select="views/view">
	<table>
	  <tr class="rowh">
	    <th colspan="4">Zones for View <xsl:value-of select="name" /></th>
	  </tr>
	  <tr class="rowh">
	    <th>Name</th>
	    <th>Class</th>
	    <th>Serial</th>
	  </tr>
          <xsl:for-each select="zones/zone">
	    <tr class="lrow">
	      <td><xsl:value-of select="name"/></td>
	      <td><xsl:value-of select="rdataclass"/></td>
	      <td><xsl:value-of select="serial"/></td>
	    </tr>
          </xsl:for-each>
        </table>
        <br />
        </xsl:for-each>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
