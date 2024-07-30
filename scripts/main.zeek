module Intel;

export {
  redef record Intel::MetaData +={
    confidence: double &optional;
    threat_score: double &optional;
    verdict: string &optional;
    verdict_source: string &optional;
    firstseen: string &optional;
    lastseen: string &optional;
    associated: string &optional;
    category: string &optional;
    campaigns: string &optional;
    reports: string &optional;
  };

  redef record Info += {
    ## The description or source of the intel.
    desc: set[string] &optional &log;
    ## The URL to find more information about the indicator.
    url: set[string] &optional &log;
    ## IC-Score: A 0-100 rating, representing the source of the intel's confidence that a particular indicator represents malicious activity.
    confidence: set[double] &optional &log;
    ## Theat Score is an analytical score from 0-100 that reflects the likelihood of a threat being malicious to an organization.  It is based on Intelligence factors such as threat severity and confidence.
    threat_score: set[double] &optional &log;
    ## The verdict tells you if the determination was malicious or benign.
    verdict: set[string] &optional &log;
    ## The verdict tells you if the verdict was determined by machine learning or an analyst.
    verdict_source: set[string] &optional &log;
    ## The first time this indicator was observed by any of the listed sources.
    firstseen: set[string] &optional &log;
    ## The most recent time this indicator was observed by any of the listed sources.
    lastseen: set[string] &optional &log;
    ## A list of actors associated with this indicator.
    associated: set[string] &optional &log;
    ## A list of categories, as defined by the source, for this indicator.
    category: set[string] &optional &log;
    ## A list of any known campaigns related to the indicator.
    campaigns: set[string] &optional &log;
    ## A list of any reports relavent to the indicator.
    reports: set[string] &optional &log;
  };
}

hook extend_match(info: Info, s: Seen, items: set[Item]) &priority=5 {
  for ( item in items ) {
    if ( item$meta?$desc ) {
      if ( !info?$desc)
        info$desc=string_set();
      add info$desc[item$meta$desc];
    }
    if ( item$meta?$url ) {
      if ( !info?$url)
        info$url=string_set();
      add info$url[item$meta$url];
    }
    if ( item$meta?$confidence ) {
      if ( !info?$confidence)
        info$confidence=set();
      add info$confidence[item$meta$confidence];
    }
    if ( item$meta?$threat_score ) {
      if ( !info?$threat_score)
        info$threat_score=set();
      add info$threat_score[item$meta$threat_score];
    }
    if ( item$meta?$verdict ) {
      if ( !info?$verdict)
        info$verdict=string_set();
      add info$verdict[item$meta$verdict];
    }
    if ( item$meta?$verdict_source ) {
      if ( !info?$verdict_source)
        info$verdict_source=string_set();
      add info$verdict_source[item$meta$verdict_source];
    }
    if ( item$meta?$firstseen ) {
      if ( !info?$firstseen)
        info$firstseen=string_set();
      add info$firstseen[item$meta$firstseen];
    }
    if ( item$meta?$lastseen ) {
      if ( !info?$lastseen)
        info$lastseen=string_set();
      add info$lastseen[item$meta$lastseen];
    }
    if ( item$meta?$associated ) {
      if ( !info?$associated)
        info$associated=string_set();
      add info$associated[item$meta$associated];
    }
    if ( item$meta?$category ) {
      if ( !info?$category)
        info$category=string_set();
      add info$category[item$meta$category];
    }
    if ( item$meta?$campaigns ) {
      if ( !info?$campaigns)
        info$campaigns=string_set();
      add info$campaigns[item$meta$campaigns];
    }
    if ( item$meta?$reports) {
      if ( !info?$reports)
        info$reports=string_set();
      add info$reports[item$meta$reports];
    }
  }
}
