module Intel;

export {
  redef record Intel::MetaData +={
    confidence: double &optional;
    firstseen: string &optional;
    lastseen: string &optional;
    associated: string &optional;
    category: string &optional;
    campaigns: string &optional;
    reports: string &optional;
  };

  redef record Info += {
    ## The description or source of the intel.
    desc: set[string] &optional &log &default=string_set();
    ## The URL to find more information about the IOC.
    url: set[string] &optional &log &default=string_set();
    ## The confidence score, based on the source in the description, that this is an IOC.
    confidence: set[double] &optional &log &default=set();
    ## The first time this IOC was observed by any of the listed sources.
    firstseen: set[string] &optional &log &default=string_set();
    ## The most recent time this IOC was observed by any of the listed sources.
    lastseen: set[string] &optional &log &default=string_set();
    ## A list of actors associated with this IOC.
    associated: set[string] &optional &log &default=string_set();
    ## A list of categories, as defined by the source, for this IOC.
    category: set[string] &optional &log &default=string_set();
    ## A list of any known campaigns related to the IOC.
    campaigns: set[string] &optional &log &default=string_set();
    ## A list of any reports relavent to the IOC.
    reports: set[string] &optional &log &default=string_set();
  };
}

hook extend_match(info: Info, s: Seen, items: set[Item]) &priority=5
  {
  for ( item in items )
    {
    if ( item$meta?$desc )
      add info$desc[item$meta$desc];
    if ( item$meta?$url )
      add info$url[item$meta$url];
    if ( item$meta?$confidence )
      add info$confidence[item$meta$confidence];
    if ( item$meta?$firstseen )
      add info$firstseen[item$meta$firstseen];
    if ( item$meta?$lastseen )
      add info$lastseen[item$meta$lastseen];
    if ( item$meta?$associated )
      add info$associated[item$meta$associated];
    if ( item$meta?$category )
      add info$category[item$meta$category];
    if ( item$meta?$campaigns )
      add info$campaigns[item$meta$campaigns];
    if ( item$meta?$reports)
      add info$reports[item$meta$reports];
    }
  }
