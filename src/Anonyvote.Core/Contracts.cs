namespace Anonyvote.Core;

// HTTP contracts, shared by the services, the simulator and the verifier.

/// <summary>What both services publish about the election. All of it is public.</summary>
public sealed record ElectionInfo(
    string Id,
    string Name,
    IReadOnlyList<Candidate> Candidates,
    int MaxChoices,
    string RegistrarPublicKeyPem,
    string ElectionPublicKeyPem,
    ElectionPhase Phase);

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
