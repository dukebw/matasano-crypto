#include "crypt_helper.h"

#define MAX_STRING_LENGTH 256
#define MAX_ENCODED_PROFILE_LENGTH (2*MAX_STRING_LENGTH)

global_variable u32 GlobalNextUid;

const char USER_STRING[] = "user";
const char EMAIL_STRING[] = "email";
const char UID_STRING[] = "uid";
const char ROLE_STRING[] = "role";
const char TEST_EMAIL[] = "foo123@bar.com";
const char ADMIN_STRING[] = "admin";

typedef struct
{
	char Email[MAX_STRING_LENGTH];
	u32 Uid;
	char Role[MAX_STRING_LENGTH];
} user_profile;

internal void
FillInMemberString(char *MemberString, char *SourceString, u32 *SourceStringIndex, u32 SourceStringLength)
{
	Stopif((MemberString == 0) || (SourceString == 0) || (SourceStringIndex == 0),
		   return,
		   "Null input to FillInMemberString");
	u32 MemberStringIndex;
	++*SourceStringIndex;
	for (MemberStringIndex = 0;
		 (*SourceStringIndex < SourceStringLength) && (SourceString[*SourceStringIndex] != '&');
		 ++MemberStringIndex, ++*SourceStringIndex)
	{
		Stopif(MemberStringIndex >= MAX_STRING_LENGTH, return, "Member string too long");
		Stopif(SourceString[*SourceStringIndex] == '=', return, "Invalid metacharacter =");
		MemberString[MemberStringIndex] = SourceString[*SourceStringIndex];
	}
	MemberString[MemberStringIndex] = 0;
}

internal inline void
CopyStringAndIncrement(char **DestString, const char *SourceString, u32 Length)
{
	Stopif((DestString == 0) || (*DestString == 0) || (SourceString == 0),
		   return,
		   "Null input to CopyStringMemberAndIncrement");
	memcpy(*DestString, SourceString, Length);
	*DestString += Length;
	*(*DestString)++ = '=';
}

internal u32
ProfileFor(char *NewUserProfile, const char *Email, u32 EmailLength)
{
	u32 EncodedProfileLength;
	char *NewUserProfileStart = NewUserProfile;
	Stopif((NewUserProfile == 0) || (Email == 0), return 0, "Null input to ProfileFor");
	Stopif(EmailLength >= MAX_STRING_LENGTH, return 0, "Email length too long in ProfileFor");

	CopyStringAndIncrement(&NewUserProfile, EMAIL_STRING, strlen(EMAIL_STRING));

	for (u32 EmailIndex = 0;
		 EmailIndex < EmailLength;
		 ++EmailIndex)
	{
		Stopif((Email[EmailIndex] == '=') || (Email[EmailIndex] == '&'),
			   return 0,
			   "Meta-character in Email in ProfileFor");
		*NewUserProfile++ = Email[EmailIndex];
	}

	*NewUserProfile++ = '&';

	CopyStringAndIncrement(&NewUserProfile, UID_STRING, strlen(UID_STRING));
	u32 UidStringLength = sprintf(NewUserProfile, "%u", GlobalNextUid++);
	Stopif(GlobalNextUid == UINT32_MAX, return 0, "Too many Uids!");
	NewUserProfile += UidStringLength;

	*NewUserProfile++ = '&';

	CopyStringAndIncrement(&NewUserProfile, ROLE_STRING, strlen(ROLE_STRING));
	memcpy(NewUserProfile, USER_STRING, sizeof(USER_STRING));

	EncodedProfileLength = (NewUserProfile + sizeof(USER_STRING)) - NewUserProfileStart;
	return EncodedProfileLength;
}

internal void
ParseUserProfile(user_profile *OutUserProfile, char *EncodedProfile, u32 EncodedProfileLength)
{
	Stopif((OutUserProfile == 0) || (EncodedProfile == 0), return, "Null inputs to ParseUserProfile");
	char StringBuffer[MAX_STRING_LENGTH];
	for (u32 TestStringIndex = 0, StringBufferIndex = 0;
		 TestStringIndex < EncodedProfileLength;
		 ++TestStringIndex)
	{
		Stopif(EncodedProfile[TestStringIndex] == '&', return, "Invalid metacharacter &");
		if (EncodedProfile[TestStringIndex] == '=')
		{
			if (memcmp(StringBuffer, EMAIL_STRING, strlen(EMAIL_STRING)) == 0)
			{
				FillInMemberString(OutUserProfile->Email, EncodedProfile, &TestStringIndex,
								   EncodedProfileLength);
			}
			else if ((memcmp(StringBuffer, ROLE_STRING, strlen(ROLE_STRING)) == 0) ||
					 (memcmp(StringBuffer, ADMIN_STRING, strlen(ADMIN_STRING)) == 0))
			{
				FillInMemberString(OutUserProfile->Role, EncodedProfile, &TestStringIndex,
								   EncodedProfileLength);
			}
			else if (memcmp(StringBuffer, UID_STRING, strlen(UID_STRING)) == 0)
			{
				++TestStringIndex;
				for (StringBufferIndex = 0;
					 (TestStringIndex < EncodedProfileLength) && (EncodedProfile[TestStringIndex] != '&');
					 ++StringBufferIndex, ++TestStringIndex)
				{
					Stopif(StringBufferIndex >= MAX_STRING_LENGTH, return, "Uid too long for StringBuffer");
					Stopif(!isdigit((i32)EncodedProfile[TestStringIndex]), return, "Non-digit in uid");
					StringBuffer[StringBufferIndex] = EncodedProfile[TestStringIndex];
				}
				StringBuffer[StringBufferIndex] = 0;
				sscanf(StringBuffer, "%u", &OutUserProfile->Uid);
			}
			else
			{
				Stopif(true, return, "Invalid profile member for assignment");
			}
			StringBufferIndex = 0;
		}
		else
		{
			StringBuffer[StringBufferIndex] = EncodedProfile[TestStringIndex];
			++StringBufferIndex;
		}
	}
}

int main()
{
	srand(time(0));

	u32 Key[AES_128_BLOCK_LENGTH_WORDS];
	GenRandUnchecked(Key, AES_128_BLOCK_LENGTH_WORDS);

	char TestEncodedProfile[MAX_STRING_LENGTH];
	u32 EncodedProfileLength = ProfileFor(TestEncodedProfile, TEST_EMAIL, strlen(TEST_EMAIL));

	u8 EncryptedProfile[MAX_ENCODED_PROFILE_LENGTH];
	AesEcbEncrypt(EncryptedProfile, (u8 *)TestEncodedProfile, EncodedProfileLength, (u8 *)Key, sizeof(Key));

	u8 EncryptedAdmin[AES_128_BLOCK_LENGTH_BYTES];
	u32 EncryptedAdminStringLength = sizeof(ADMIN_STRING);
	u8 PaddedAdminMessage[AES_128_BLOCK_LENGTH_BYTES];
	memcpy(PaddedAdminMessage, ADMIN_STRING, EncryptedAdminStringLength);
	AesEcbEncrypt(EncryptedAdmin, PaddedAdminMessage, EncryptedAdminStringLength, (u8 *)Key, sizeof(Key));

	u32 ProfileLengthNoUser = EncodedProfileLength - sizeof(USER_STRING);
	memcpy(EncryptedProfile + ProfileLengthNoUser, EncryptedAdmin, AES_128_BLOCK_LENGTH_BYTES);

	EncodedProfileLength = ProfileLengthNoUser + EncryptedAdminStringLength;
	AesEcbDecrypt((u8 *)TestEncodedProfile, (u8 *)EncryptedProfile, EncodedProfileLength,
				  (u8 *)Key, sizeof(Key));

	printf("%s\n", TestEncodedProfile);

	user_profile TestUserProfile;
	ParseUserProfile(&TestUserProfile, TestEncodedProfile, EncodedProfileLength);
}
