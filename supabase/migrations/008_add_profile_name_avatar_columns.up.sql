alter table user_profiles add column if not exists name text;
alter table user_profiles add column if not exists avatar text;

update user_profiles set name = full_name where name is null and full_name is not null;
update user_profiles set avatar = avatar_url where avatar is null and avatar_url is not null;
