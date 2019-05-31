create table if not exists "APT"
(
  apt_name    text                                               not null
    constraint "APT_pkey"
      primary key,
  created     timestamp with time zone default CURRENT_TIMESTAMP not null,
  last_update timestamp with time zone default CURRENT_TIMESTAMP not null
);

alter table "APT"
  owner to analyst;

create trigger set_timestamp
  before update
  on "APT"
  for each row
execute procedure trigger_set_timestamp();

create table if not exists "REPORTS"
(
  report_id   bigserial                                          not null
    constraint "REPORTS_pkey"
      primary key,
  hash        text
    constraint hash_unique
      unique,
  url         text
    constraint url_unique
      unique,
  description text,
  source      text,
  created     timestamp with time zone default CURRENT_TIMESTAMP not null,
  last_update timestamp with time zone default CURRENT_TIMESTAMP not null
);

alter table "REPORTS"
  owner to analyst;

create trigger set_timestamp
  before update
  on "REPORTS"
  for each row
execute procedure trigger_set_timestamp();

create table if not exists "APT_REPORT"
(
  apt_name    text   not null
    constraint "APT_REPORT_apt_name_fkey"
      references "APT",
  report_id   bigint not null
    constraint "APT_REPORT_report_id_fkey"
      references "REPORTS",
  created     timestamp with time zone default CURRENT_TIMESTAMP,
  last_update timestamp with time zone default CURRENT_TIMESTAMP,
  constraint "APT_REPORT_pkey"
    primary key (apt_name, report_id)
);

alter table "APT_REPORT"
  owner to analyst;

create trigger set_timestamp
  before update
  on "APT_REPORT"
  for each row
execute procedure trigger_set_timestamp();

create table if not exists "SAMPLES"
(
  sample_id   bigserial                                          not null
    constraint "SAMPLES_pkey"
      primary key,
  md5         text
    constraint "SAMPLES_md5_key"
      unique,
  sha1        text
    constraint "SAMPLES_sha1_key"
      unique,
  sha256      text
    constraint "SAMPLES_sha256_key"
      unique,
  sha512      text
    constraint "SAMPLES_sha512_key"
      unique,
  created     timestamp with time zone default CURRENT_TIMESTAMP not null,
  last_update timestamp with time zone default CURRENT_TIMESTAMP not null
);

alter table "SAMPLES"
  owner to analyst;

create trigger set_timestamp
  before update
  on "SAMPLES"
  for each row
execute procedure trigger_set_timestamp();

create table if not exists "SAMPLE_REPORT"
(
  sample_id   bigint not null
    constraint "SAMPLE_REPORT_sample_id_fkey"
      references "SAMPLES",
  report_id   bigint not null
    constraint "SAMPLE_REPORT_report_id_fkey"
      references "REPORTS",
  created     timestamp with time zone default CURRENT_TIMESTAMP,
  last_update timestamp with time zone default CURRENT_TIMESTAMP,
  constraint "SAMPLE_REPORT_pkey"
    primary key (sample_id, report_id)
);

alter table "SAMPLE_REPORT"
  owner to analyst;

create trigger set_timestamp
  before update
  on "SAMPLE_REPORT"
  for each row
execute procedure trigger_set_timestamp();

create table if not exists "UNKNOWN_REPORTS"
(
  report_id   bigint                   default nextval('"REPORTS_REPORT_ID_seq"'::regclass) not null
    constraint "UNKNOWN_REPORTS_pkey"
      primary key,
  hash        text
    constraint "UNKNOWN_HASH_unique"
      unique,
  url         text
    constraint "UNKNOWN_URL_unique"
      unique,
  description text,
  source      text,
  created     timestamp with time zone default CURRENT_TIMESTAMP                            not null,
  last_update timestamp with time zone default CURRENT_TIMESTAMP                            not null
);

alter table "UNKNOWN_REPORTS"
  owner to analyst;

create trigger set_timestamp
  before update
  on "UNKNOWN_REPORTS"
  for each row
execute procedure trigger_set_timestamp();

create table if not exists "KEYWORDS"
(
  keyword     text                                               not null
    constraint "KEYWORDS_pkey"
      primary key,
  is_alias    boolean                  default false             not null,
  apt_name    text
    constraint "KEYWORDS_apt_name_fkey"
      references "APT",
  created     timestamp with time zone default CURRENT_TIMESTAMP not null,
  last_update timestamp with time zone default CURRENT_TIMESTAMP not null,
  constraint if_is_alias_apt_not_null
    check ((NOT "IS_ALIAS") OR ("APT_NAME" IS NOT NULL))
);

alter table "KEYWORDS"
  owner to analyst;

create trigger set_timestamp
  before update
  on "KEYWORDS"
  for each row
execute procedure trigger_set_timestamp();

create table if not exists "SOFTWARE"
(
  software  text                  not null,
  is_tool   boolean default false not null,
  report_id bigserial             not null
);

alter table "SOFTWARE"
  owner to analyst;

