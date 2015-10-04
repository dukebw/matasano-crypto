#include "crypt_helper.h"

#define MAX_STRING_LENGTH 256
#define MAX_ENCODED_PROFILE_LENGTH (2*MAX_STRING_LENGTH)

global_variable u32 GlobalNextUid;

const char USER_STRING[] = "user";
const char EMAIL_STRING[] = "email";
const char UID_STRING[] = "uid";
const char ROLE_STRING[] = "role";
const char TEST_EMAIL[] = "foo@bar.com";

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

int main()
{
	char TestString[] = "email=foo@bar.com&uid=10&role=user";
	user_profile TestUserProfile;
	memset(&TestUserProfile, 0, sizeof(TestUserProfile));

	char StringBuffer[MAX_STRING_LENGTH];
	u32 TestStringLength = strlen(TestString);
	for (u32 TestStringIndex = 0, StringBufferIndex = 0;
		 TestStringIndex < TestStringLength;
		 ++TestStringIndex)
	{
		Stopif(TestString[TestStringIndex] == '&', return EXIT_FAILURE, "Invalid metacharacter &");
		if (TestString[TestStringIndex] == '=')
		{
			if (memcmp(StringBuffer, EMAIL_STRING, strlen(EMAIL_STRING)) == 0)
			{
				FillInMemberString(TestUserProfile.Email, TestString, &TestStringIndex, TestStringLength);
			}
			else if (memcmp(StringBuffer, ROLE_STRING, strlen(ROLE_STRING)) == 0)
			{
				FillInMemberString(TestUserProfile.Role, TestString, &TestStringIndex, TestStringLength);
			}
			else if (memcmp(StringBuffer, UID_STRING, strlen(UID_STRING)) == 0)
			{
				++TestStringIndex;
				for (StringBufferIndex = 0;
					 (TestStringIndex < TestStringLength) && (TestString[TestStringIndex] != '&');
					 ++StringBufferIndex, ++TestStringIndex)
				{
					Stopif(StringBufferIndex >= MAX_STRING_LENGTH,
						   return EXIT_FAILURE,
						   "Uid too long for StringBuffer");
					Stopif(!isdigit((i32)TestString[TestStringIndex]), return EXIT_FAILURE, "Non-digit in uid");
					StringBuffer[StringBufferIndex] = TestString[TestStringIndex];
				}
				StringBuffer[StringBufferIndex] = 0;
				sscanf(StringBuffer, "%u", &TestUserProfile.Uid);
			}
			else
			{
				Stopif(true, return EXIT_FAILURE, "Invalid profile member for assignment");
			}
			StringBufferIndex = 0;
		}
		else
		{
			StringBuffer[StringBufferIndex] = TestString[TestStringIndex];
			++StringBufferIndex;
		}
	}

	srand(time(0));

	u32 Key[AES_128_BLOCK_LENGTH_WORDS];
	GenRandUnchecked(Key, AES_128_BLOCK_LENGTH_WORDS);
	u32 EncodedProfileLength = ProfileFor(StringBuffer, TEST_EMAIL, strlen(TEST_EMAIL));
	u8 EncryptedProfile[MAX_ENCODED_PROFILE_LENGTH];
	AesEcbEncrypt(EncryptedProfile, (u8 *)StringBuffer, EncodedProfileLength, (u8 *)Key, sizeof(Key));
}
