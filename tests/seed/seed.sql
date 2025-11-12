-- Clear any existing data before seeding:
delete from auth.users;
delete from auth.sessions;

-- Insert some basic users:
insert into auth.users (id, email, password_hash, email_confirmed_at, created_at, updated_at) values
   ('f968d0ab-858c-4cab-b8fb-575a814ea738', 'alice@example.com', '$2a$10$OuCVNjUHXJRAdOpc4b/1bOiCHRSE3XsMTVTFVIM.EEdh8h7U9RK.G', '2024-01-01 10:00:00', '2024-01-01 09:00:00', '2024-01-01 09:00:00'),
   ('6d73123a-8ec4-409d-8555-c638c74ba89d', 'carol@example.com', '$2a$10$OuCVNjUHXJRAdOpc4b/1bOiCHRSE3XsMTVTFVIM.EEdh8h7U9RK.G', '2024-01-01 12:30:00', '2024-01-03 08:00:00', '2024-01-03 08:00:00'),
   ('496d14fe-0964-40b3-ac72-b1ad0b23dea9', 'eve@example.com', '$2a$10$OuCVNjUHXJRAdOpc4b/1bOiCHRSE3XsMTVTFVIM.EEdh8h7U9RK.G', '2024-01-05 15:00:00', '2024-01-05 10:00:00', '2024-01-05 10:00:00');

-- Insert a user requiring signup confirmation:
insert into auth.users (id, email, password_hash, confirmation_token, confirmation_token_created_at, email_confirmed_at, created_at, updated_at) values
    ('d1f44dba-9cab-43d2-aecf-ed0b1cd9b406',
     'bob@example.com',
     '$2a$10$OuCVNjUHXJRAdOpc4b/1bOiCHRSE3XsMTVTFVIM.EEdh8h7U9RK.G',
     'confirmation-token',
     now(),
     null,
     now(),
     now());

-- Insert a user with an expired signup confirmation:
insert into auth.users (id, email, password_hash, confirmation_token, confirmation_token_created_at, email_confirmed_at, created_at, updated_at) values
    ('e229a663-1730-4af6-ac02-f3e10a2accaf',
     'teddy@example.com',
     '$2a$10$OuCVNjUHXJRAdOpc4b/1bOiCHRSE3XsMTVTFVIM.EEdh8h7U9RK.G',
     'confirmation-token',
     now() - interval '2 hours',
     null,
     now() - interval '2 hours',
     now() - interval '2 hours');

-- Insert a user with an expired email change token:
insert into auth.users (id, email, password_hash, email_confirmed_at, email_change, email_change_token, email_change_requested_at, encrypted_otp, otp_created_at, created_at, updated_at) values
    ('2ce46a7c-a0cc-407a-8e1d-75c6317d1cfe',
     'enoch@example.com',
     '$2a$10$OuCVNjUHXJRAdOpc4b/1bOiCHRSE3XsMTVTFVIM.EEdh8h7U9RK.G',
     now() - interval '10 days',
     'enoch.new@example.com',
     'eed9550b-978a-4ddc-922e-7be5bd8e4d24',
     now() - interval '1 days',
     '$2a$10$PK8BS6phkRiFw/g5nHRoT.IcEnpjstCvmP.XyjlTT.IZbNpv8yDTK', -- 654321
     now() - interval '1 days',
     now() - interval '10 days',
     now() - interval '10 days');
