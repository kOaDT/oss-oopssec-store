import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getAuthenticatedUser } from "@/lib/server-auth";

const ALLOWED_USER_FIELDS = ["id", "email", "role", "addressId", "password"];

function toCSV(data: Record<string, unknown>[]): string {
  if (data.length === 0) return "";

  const headers = Object.keys(data[0]);
  const csvRows = [headers.join(",")];

  for (const row of data) {
    const values = headers.map((header) => {
      const value = row[header];
      if (value === null || value === undefined) return "";
      const stringValue = String(value);
      if (
        stringValue.includes(",") ||
        stringValue.includes('"') ||
        stringValue.includes("\n")
      ) {
        return `"${stringValue.replace(/"/g, '""')}"`;
      }
      return stringValue;
    });
    csvRows.push(values.join(","));
  }

  return csvRows.join("\n");
}

async function getSystemDiagnostics() {
  const diagnostics: Record<string, unknown> = {
    timestamp: new Date().toISOString(),
    nodeVersion: process.version,
    environment: process.env.NODE_ENV,
  };

  try {
    diagnostics.database = {
      connected: true,
      version: "Prisma Client v6.19.1",
    };

    const flag = await prisma.flag.findUnique({
      where: { slug: "information-disclosure-api-error" },
    });
    diagnostics.featureFlags = flag?.flag;
  } catch (dbErr) {
    diagnostics.database = {
      connected: false,
      stack: dbErr instanceof Error ? dbErr.stack : undefined,
      error: dbErr instanceof Error ? dbErr.message : String(dbErr),
    };
  }

  return diagnostics;
}

export async function POST(request: NextRequest) {
  try {
    const user = await getAuthenticatedUser(request);

    if (!user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const body = await request.json();
    const { format, fields } = body;

    if (!format || !fields) {
      return NextResponse.json(
        { error: "Missing required fields: format and fields" },
        { status: 400 }
      );
    }

    const requestedFields = fields
      .split(",")
      .map((f: string) => f.trim())
      .filter((f: string) => f.length > 0);

    if (requestedFields.length === 0) {
      return NextResponse.json(
        { error: "No valid fields specified" },
        { status: 400 }
      );
    }

    const invalidFields = requestedFields.filter(
      (f: string) => !ALLOWED_USER_FIELDS.includes(f)
    );

    if (invalidFields.length > 0) {
      const diagnostics = await getSystemDiagnostics();

      return NextResponse.json(
        {
          error: "Invalid field names in export request",
          invalidFields: invalidFields,
          allowedFields: ALLOWED_USER_FIELDS,
          debug: {
            message: "Export failed due to invalid field specification",
            requestedFields: requestedFields,
            systemDiagnostics: diagnostics,
          },
        },
        { status: 400 }
      );
    }

    const userData = await prisma.user.findUnique({
      where: { id: user.id },
      include: { address: true },
    });

    if (!userData) {
      return NextResponse.json({ error: "User not found" }, { status: 404 });
    }

    const exportData: Record<string, unknown> = {};
    for (const field of requestedFields) {
      if (field === "addressId") {
        exportData[field] = userData.addressId;
      } else if (field in userData) {
        exportData[field] = userData[field as keyof typeof userData];
      }
    }

    if (format === "csv") {
      const csvData = toCSV([exportData]);
      return new NextResponse(csvData, {
        headers: {
          "Content-Type": "text/csv",
          "Content-Disposition": "attachment; filename=user-data.csv",
        },
      });
    }

    return NextResponse.json({
      data: exportData,
      format,
    });
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : String(error);

    const diagnostics = await getSystemDiagnostics();

    return NextResponse.json(
      {
        error: "Failed to export user data",
        details: errorMessage,
        debug: {
          systemDiagnostics: diagnostics,
        },
      },
      { status: 500 }
    );
  }
}
