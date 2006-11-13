<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
   xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
   xmlns="http://www.w3.org/1999/xhtml">
  <xsl:template match="isc/bind">
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
        <div class="header">Bind 9 Configuration and Statistics Report</div>

	<br/>

	<table>

	  <tr class="rowh">
            <th colspan="2">Zone Configuration Parameters</th>
          </tr>

	  <tr class="row"><td>
          <span class="item">Maximum transfers in:</span>
	  </td><td>
	  <span class="value">
	    <xsl:value-of select="statistics/zonemanager/config/transfersin"/>
          </span>
	  </td></tr>

	  <tr class="row"><td>
          <span class="item">Transfers per name server:</span>
	  </td><td>
	  <span class="value">
	    <xsl:value-of
		select="statistics/zonemanager/config/transfersperns"/>
          </span>
	  </td></tr>

	  <tr class="row"><td>
          <span class="item">Serial query rate:</span>
	  </td><td>
	  <span class="value">
	    <xsl:value-of
		select="statistics/zonemanager/config/serialqueryrate"/>
          </span>
	  </td></tr>

	  <tr class="row"><td>
          <span class="item">I/O limit:</span>
	  </td><td>
	  <span class="value">
	    <xsl:value-of
		select="statistics/zonemanager/config/iolimit"/>
          </span>
	  </td></tr>

	</table>

	<br />

	<table>
	  <tr class="rowh">
            <th colspan="2">Current Zone Statistics</th>
          </tr>
	  <tr class="row"><td>
          <span class="item">Transfers Active:</span>
	  </td><td>
	  <span class="value">
	    <xsl:value-of select="statistics/zonemanager/status/ioactive"/>
          </span>
	  </td></tr>
	</table>

	<br />

	<table>
	  <tr class="rowh"><th colspan="2">Zone List</th></tr>
	  <tr class="rowh"><th>Name</th><th>Serial</th></tr>
          <xsl:for-each select="/isc/bind/statistics/zonemanager/zones/zone">
	    <tr class="lrow">
	      <td><xsl:value-of select="name"/></td>
	      <td><xsl:value-of select="serial"/></td>
	    </tr>
          </xsl:for-each>
        </table>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
