namespace Anonyvote.Core;

// HTTP contracts, shared by the services, the simulator and the verifier.

/// <summary>
/// What both services publish about the election. All of it is public.
///
/// <paramref name="SourceUrl"/> is where this deployment's source code can be obtained. The
/// AGPL's section 13 obliges whoever modifies Anonyvote and runs an election through it to
/// offer that source to the voters using it; announcing it here means the pages can put the
/// link in front of them instead of relying on the operator to remember.
/// </summary>
public sealed record ElectionInfo(
    string Id,
    string Name,
    IReadOnlyList<Candidate> Candidates,
    int MaxChoices,
    string RegistrarPublicKeyPem,
    string ElectionPublicKeyPem,
    ElectionPhase Phase,
    string? SourceUrl = null);

/// <summary>Phase 1: a census code plus the blinded message the registrar cannot read.</summary>
public sealed record RegisterRequest(string Code, string BlindedMessage);

public sealed record RegisterResponse(string BlindSignature);

/// <summary>Phase 2: an anonymous credential and an encrypted ballot. No authentication at all.</summary>
public sealed record CastRequest(string Message, string Signature, string Ciphertext);

/// <summary>The voter's receipt: with it they can check their vote is on the board.</summary>
public sealed record CastResponse(long Index, string EntryHash, string Head);

public sealed record BoardHead(long Count, string Head);

public sealed record BoardPage(long Count, string Head, IReadOnlyList<BoardEntry> Entries);

public sealed record ErrorResponse(string Error);
