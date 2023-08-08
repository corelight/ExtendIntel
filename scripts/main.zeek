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
    ##
    desc: set[string] &optional &log &default=string_set();
    url: set[string] &optional &log &default=string_set();
    confidence: set[double] &optional &log &default=set();
    firstseen: set[string] &optional &log &default=string_set();
    lastseen: set[string] &optional &log &default=string_set();
    associated: set[string] &optional &log &default=string_set();
    category: set[string] &optional &log &default=string_set();
    campaigns: set[string] &optional &log &default=string_set();
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
