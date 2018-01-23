package com.hpoo.runFlow;

import com.dynatrace.diagnostics.pdk.*;

import java.util.Collection;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;


import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;

public class RunFlow implements Action {

	private static final Logger log = Logger.getLogger(RunFlow.class.getName());

	@Override
	public Status setup(ActionEnvironment env) throws Exception {
		return new Status(Status.StatusCode.Success);
	}

	@Override
	public Status execute(ActionEnvironment env) throws Exception {
		log.info("############################ START of Incident Processing ###########################");
		String hpooURL = env.getConfigUrl("hpooURL").toString();
		String flowParam = env.getConfigString("flowParam");
		String incidentHost = "";
		String guid = "";
		String agentName = "";
		String incidentName = "";
		String startTime = "";
		String severity = "";
		String systemProfile = "";
		String dynaTraceServer = "";
		String incidentInstance = "";
		String incidentInstanceType = "";
		String measureValue = "";
		String measureUnit = "";
		String thresholdValue = "";
		String incidentMessage = "";

		String URL = hpooURL;

		log.fine(URL);

		// If Parameters call for incident host determine the hostname from the
		// incident
		//flowParam = URL;

		if (flowParam != null && !flowParam.equals("")) {
			log.fine("Parameter Parsing Started");
			Collection<Incident> incidents = env.getIncidents();
			for (Incident i : incidents) {
				incidentMessage = i.getMessage();
				dynaTraceServer = i.getServerName();
				severity = getSeverityAsString(i);
				incidentName = i.getIncidentRule().getName();
				startTime = i.getStartTime().toString();
				guid = i.getKey().getUUID();
				systemProfile = env.getSystemProfileName();
				Collection<Violation> violations = i.getViolations();
				for (Violation v : violations) {
					Measure violatedMeasure = v.getViolatedMeasure();
					Source source = violatedMeasure.getSource();
					for (Violation.TriggerValue vt : v.getTriggerValues()) {
						measureValue = vt.getValue().toString().replaceAll("[a-zA-Z[%]]", "");
					}
					measureUnit = violatedMeasure.getUnit().toString();
					thresholdValue = v.getViolatedThreshold().getValue().toString().replace(".00", "");
					log.info("Before if Sourcetype");
					if (source.getSourceType() == SourceType.Monitor) {
						// Debugging
						//Monitor monitor = (MonitorSource)source;
                        MonitorSource monitorSource;
						String monitorName = (monitorSource = (MonitorSource)source).getName();
						//String monitorName = monitor.getName();
						//String monitorStatus = (monitor = (MonitorSource)source).getMessage();
						//log.info("Monitorname " + monitorName);
						//log.info("Monitorname " + monitorStatus);
						// debugging
						String sMeasure = violatedMeasure.getName();
						if(sMeasure.contains("@"))
						{
							log.finer("Measure: "+ sMeasure);
							incidentHost = StringUtils.substringAfter(sMeasure, "@");
							incidentHost = StringUtils.substringBefore(incidentHost,")");
							log.finer("Measure Host: "+ incidentHost);
						}
						String pat = "\\[.*-\\>(.*?)\\]";
						Pattern pattern = Pattern.compile(pat);
						Matcher matches = pattern.matcher(sMeasure);
						while (matches.find()) {
							// log.fine(matches.group());
							incidentInstanceType = StringUtils
									.substringBetween(sMeasure, "[", "->");
							// log.fine(incidentInstanceType);
							incidentInstance = StringUtils.substringBetween(
									sMeasure, "->", "]");
							// log.fine(incidentInstance);
						}

					} else if (source.getSourceType() == SourceType.Agent) {
						String AgentHostName = ((AgentSource) source).getHost().toString();
						agentName = ((AgentSource) source).getName().toString();
						log.fine("Agent type measure.");
						incidentHost = AgentHostName;
						
						// log.fine(incidentHost);
					}
					log.info("After if Sourcetype");



				}
				// Replace all variables
				if (flowParam.contains("{$host}")) {
					log.fine("*****Host Found!*****");
					Pattern p = Pattern.compile("(\\Q{$host}\\E)");
					Matcher matches = p.matcher(flowParam);
					flowParam = matches.replaceAll(encodeURIComponent(incidentHost));
					log.fine(flowParam);
				}
				if (flowParam.contains("{$guid}")) {
					log.fine("*****GUID Found!*****");
					Pattern p = Pattern.compile("(\\Q{$guid}\\E)");
					Matcher matches = p.matcher(flowParam);
					flowParam = matches.replaceAll(guid);
					log.fine(flowParam);
				}
				if (flowParam.contains("{$agent}")) {
					log.fine("*****Agent Found!*****");
					Pattern p = Pattern.compile("(\\Q{$agent}\\E)");
					Matcher matches = p.matcher(flowParam);
					flowParam = matches.replaceAll(encodeURIComponent(agentName));
					log.fine(flowParam);
				}
				if (flowParam.contains("{$incident}")) {
					log.fine("*****Incident Found!*****");
					Pattern p = Pattern.compile("(\\Q{$incident}\\E)");
					Matcher matches = p.matcher(flowParam);
					flowParam = matches.replaceAll(encodeURIComponent(incidentName));
					log.fine(flowParam);
				}
				if (flowParam.contains("{$startTime}")) {
					log.fine("*****Start Time Found!*****");
					Pattern p = Pattern.compile("(\\Q{$startTime}\\E)");
					Matcher matches = p.matcher(flowParam);
					flowParam = matches.replaceAll(encodeURIComponent(startTime));
					log.fine(flowParam);
				}
				if (flowParam.contains("{$severity}")) {
					log.fine("*****Severity Found!*****");
					Pattern p = Pattern.compile("(\\Q{$severity}\\E)");
					Matcher matches = p.matcher(flowParam);
					flowParam = matches.replaceAll(severity);
					log.fine(flowParam);
				}
				if (flowParam.contains("{$profile}")) {
					log.fine("*****Profile Found!*****");
					Pattern p = Pattern.compile("(\\Q{$profile}\\E)");
					Matcher matches = p.matcher(flowParam);
					flowParam = matches.replaceAll(systemProfile);
					log.fine(flowParam);
				}
				if (flowParam.contains("{$dynaTrace}")) {
					log.fine("*****dynaTrace Found!*****");
					Pattern p = Pattern.compile("(\\Q{$dynaTrace}\\E)");
					Matcher matches = p.matcher(flowParam);
					flowParam = matches.replaceAll(encodeURIComponent(dynaTraceServer));
					log.fine(flowParam);
				}
				if (flowParam.contains("{$instance}")) {
					log.fine("*****Instance Found!*****");
					Pattern p = Pattern.compile("(\\Q{$instance}\\E)");
					Matcher matches = p.matcher(flowParam);
					flowParam = matches.replaceAll(incidentInstance);
					log.fine(flowParam);
				}
				if (flowParam.contains("{$instanceType}")) {
					log.fine("*****Instance Type Found!*****");
					Pattern p = Pattern.compile("(\\Q{$instanceType}\\E)");
					Matcher matches = p.matcher(flowParam);
					flowParam = matches.replaceAll(incidentInstanceType);
					log.fine(flowParam);
				}
				if (flowParam.contains("{$measureValue}")) {
					log.fine("*****Measure Value Found!*****");
					Pattern p = Pattern.compile("(\\Q{$measureValue}\\E)");
					Matcher matches = p.matcher(flowParam);
					flowParam = matches.replaceAll(encodeURIComponent(measureValue));
					log.fine(flowParam);
				}
				if (flowParam.contains("{$measureUnit}")) {
					log.fine("*****Measure Unit Found!*****");
					Pattern p = Pattern.compile("(\\Q{$measureUnit}\\E)");
					Matcher matches = p.matcher(flowParam);
					flowParam = matches.replaceAll(encodeURIComponent(measureUnit));
					log.fine(flowParam);
				}
				if (flowParam.contains("{$thresholdValue}")) {
					log.fine("*****Threshold Value Found!*****");
					Pattern p = Pattern.compile("(\\Q{$thresholdValue}\\E)");
					Matcher matches = p.matcher(flowParam);
					flowParam = matches.replaceAll(encodeURIComponent(thresholdValue));
					log.fine(flowParam);
				}
				if (flowParam.contains("{$incidentMessage}")) {
					log.fine("*****Threshold Value Found!*****");
					Pattern p = Pattern.compile("(\\Q{$incidentMessage}\\E)");
					Matcher matches = p.matcher(flowParam);
					//flowParam = matches.replaceAll(incidentMessage);
					flowParam = matches.replaceAll(encodeURIComponent(incidentMessage));
					log.fine(flowParam);
				}
				// Add flow escaped parameters to web call
				String[] parameters = flowParam.split("\\r?\\n");
				for (int x = 0; x < parameters.length; x++) {
					String line = parameters[x];
					line = StringEscapeUtils.escapeHtml4(line);
					if (x != 0) {
						line = "&" + line;
					}
					//URL += line;
				}

				URL = hpooURL + "?" + flowParam;
				log.info("Evry Mercury Final Address: " + URL);
				String hpooRun = URLdownload.getURLString(URL, "empty", "empty");
				log.info("Evry Mercury return: " + hpooRun);
				log.info("############################ End of Evry Mercury Processing #############################");
			}

		}
		return new Status(Status.StatusCode.Success, (String) flowParam);
	}


	public String encodeURIComponent(String input) {
		String s = "";
		try {
			s = URLEncoder.encode(input, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return s;
	}


	@Override
	public void teardown(ActionEnvironment env) throws Exception {
	}

	private String getSeverityAsString(Incident incident) {
		if (incident.getSeverity() != null) {
			switch (incident.getSeverity()) {
			case Error:
				return "Critical";
			case Informational:
				return "Information";
			case Warning:
				return "Warning";
			}
		}
		return "";
	}
}
