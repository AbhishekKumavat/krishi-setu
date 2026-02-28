'use client';
import { useFirestore, useUser } from '@/firebase';
import { useCollection } from '@/firebase/firestore/use-collection';
import { collection, orderBy, query, Timestamp } from 'firebase/firestore';
import Link from 'next/link';
import { Card, CardDescription, CardHeader, CardTitle, CardFooter } from '../ui/card';
import { Button } from '../ui/button';
import { Edit, MoreVertical, Plus, Trash2 } from 'lucide-react';
import { CreateCommunityDialog } from './create-community-dialog';
import { useMemo, useState } from 'react';
import Image from 'next/image';
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { EditCommunityDialog } from './edit-community-dialog';
import {
    AlertDialog,
    AlertDialogAction,
    AlertDialogCancel,
    AlertDialogContent,
    AlertDialogDescription,
    AlertDialogFooter,
    AlertDialogHeader,
    AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { useAuthActions } from '@/hooks/use-auth-actions';
import { useToast } from '@/hooks/use-toast';
import { useUserProfileDialog } from '@/context/user-profile-dialog-provider';
import { formatUsername, formatTimestamp } from '@/lib/utils';
import type { Community } from '@/lib/actions/community';

export function CommunityListClient() {
    const { user } = useUser();
    const firestore = useFirestore();
    const { deleteCommunity } = useAuthActions();
    const { toast } = useToast();
    const { showProfile } = useUserProfileDialog();

    const [communityToEdit, setCommunityToEdit] = useState<Community | null>(null);
    const [communityToDelete, setCommunityToDelete] = useState<Community | null>(null);

    const STATIC_CITIES = useMemo(() => [
        {
            id: 'jalgaon-hub',
            name: 'Jalgaon Farmers',
            description: 'A community for farmers in Jalgaon to discuss Banana, Cotton, and local market trends.',
            bannerUrl: 'https://images.unsplash.com/photo-1595859702816-43c3d52d9b62?auto=format&fit=crop&q=80&w=600',
            creatorId: 'system',
            creatorUsername: 'KrishiSetu',
            postCount: 142,
            createdAt: Timestamp.now(),
            isStatic: true
        },
        {
            id: 'nashik-hub',
            name: 'Nashik Grape Growers',
            description: 'Connect with vineyards, export specialists, and vegetable growers in the Nashik region.',
            bannerUrl: 'https://images.unsplash.com/photo-1542838132-92c53300491e?auto=format&fit=crop&q=80&w=600',
            creatorId: 'system',
            creatorUsername: 'KrishiSetu',
            postCount: 89,
            createdAt: Timestamp.now(),
            isStatic: true
        },
        {
            id: 'pune-hub',
            name: 'Pune Agri-Hub',
            description: 'Discuss modern farming techniques, greenhouse setups, and direct-to-consumer sales in Pune.',
            bannerUrl: 'https://images.unsplash.com/photo-1605371924599-2d0365da1ae0?auto=format&fit=crop&q=80&w=600',
            creatorId: 'system',
            creatorUsername: 'KrishiSetu',
            postCount: 256,
            createdAt: Timestamp.now(),
            isStatic: true
        },
        {
            id: 'nagpur-hub',
            name: 'Nagpur Orange City',
            description: 'Dedicated to citrus farmers, cotton growers, and central Maharashtra agricultural discussions.',
            bannerUrl: 'https://images.unsplash.com/photo-1488459716781-31db52582fe9?auto=format&fit=crop&q=80&w=600',
            creatorId: 'system',
            creatorUsername: 'KrishiSetu',
            postCount: 115,
            createdAt: Timestamp.now(),
            isStatic: true
        }
    ], []);


    const communitiesQuery = useMemo(() => {
        if (!firestore) return null;
        return query(collection(firestore, 'communities'), orderBy('createdAt', 'desc'));
    }, [firestore]);

    const { data: communities, loading } = useCollection<Community>(communitiesQuery);

    const handleDelete = async () => {
        if (!communityToDelete) return;
        try {
            await deleteCommunity(communityToDelete.id);
            toast({ title: "Community Deleted", description: `c/${communityToDelete.id} has been removed.` });
        } catch (error: any) {
            toast({ variant: 'destructive', title: 'Error deleting community', description: error.message });
        }
        setCommunityToDelete(null);
    };

    return (
        <div className="relative">
            <div className='grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6'>
                {loading && Array.from({ length: 3 }).map((_, i) => (
                    <Card key={i} className="h-[320px] animate-pulse bg-muted/50"></Card>
                ))}

                {[...STATIC_CITIES, ...(communities || [])].map((community: any) => {
                    const isCreator = user?.uid === community.creatorId && !community.isStatic;
                    return (
                        <Card key={community.id} className="flex flex-col overflow-hidden transition-all duration-300 hover:shadow-lg hover:-translate-y-1 h-[340px]">
                            <Link href={`/c/${community.id}`} className="relative block h-40 w-full bg-muted">
                                {community.bannerUrl && (
                                    <Image
                                        src={community.bannerUrl}
                                        alt={community.name}
                                        fill
                                        className="object-cover"
                                    />
                                )}
                            </Link>
                            <CardHeader className="relative flex-1">
                                <Link href={`/c/${community.id}`}>
                                    <CardTitle className="font-headline text-xl hover:underline">c/{community.name}</CardTitle>
                                </Link>
                                <CardDescription className="line-clamp-2 mt-1">{community.description}</CardDescription>
                                {isCreator && (
                                    <DropdownMenu>
                                        <DropdownMenuTrigger asChild>
                                            <Button variant="ghost" size="icon" className="absolute top-2 right-2 h-8 w-8">
                                                <MoreVertical className="h-4 w-4" />
                                            </Button>
                                        </DropdownMenuTrigger>
                                        <DropdownMenuContent align="end">
                                            <DropdownMenuItem onClick={() => setCommunityToEdit(community)}>
                                                <Edit className="mr-2 h-4 w-4" />
                                                <span>Edit</span>
                                            </DropdownMenuItem>
                                            <DropdownMenuItem
                                                onClick={() => setCommunityToDelete(community)}
                                                className="text-destructive"
                                            >
                                                <Trash2 className="mr-2 h-4 w-4" />
                                                <span>Delete</span>
                                            </DropdownMenuItem>
                                        </DropdownMenuContent>
                                    </DropdownMenu>
                                )}
                            </CardHeader>
                            <CardFooter className="mt-auto flex justify-between text-xs text-muted-foreground border-t bg-muted/20 pt-3 pb-3">
                                {community.isStatic ? (
                                    <span>Official Hub • {community.postCount} Posts</span>
                                ) : (
                                    <button onClick={() => showProfile(community.creatorUsername)} className="hover:underline">
                                        Created by {formatUsername(community.creatorUsername, community.creatorRole)}
                                    </button>
                                )}
                                <span>{formatTimestamp(community.createdAt)}</span>
                            </CardFooter>
                        </Card>
                    )
                })}
                {user && (
                    <CreateCommunityDialog>
                        <Card className="flex flex-col items-center justify-center h-[340px] cursor-pointer border-dashed border-2 hover:bg-muted/50 transition-colors">
                            <div className="bg-primary/10 text-primary h-16 w-16 rounded-full flex items-center justify-center mb-4">
                                <Plus className="h-8 w-8" />
                            </div>
                            <h3 className="font-headline font-semibold text-lg">Create New Community</h3>
                            <p className="text-muted-foreground text-sm mt-2 text-center px-6">Don't see your city or crop? Start a new local hub!</p>
                        </Card>
                    </CreateCommunityDialog>
                )}
            </div>

            {communityToEdit && (
                <EditCommunityDialog
                    isOpen={!!communityToEdit}
                    onOpenChange={(open) => !open && setCommunityToEdit(null)}
                    community={communityToEdit}
                />
            )}

            <AlertDialog open={!!communityToDelete} onOpenChange={(open) => !open && setCommunityToDelete(null)}>
                <AlertDialogContent>
                    <AlertDialogHeader>
                        <AlertDialogTitle>Are you sure?</AlertDialogTitle>
                        <AlertDialogDescription>
                            This action cannot be undone. This will permanently delete the <strong>c/{communityToDelete?.name}</strong> community and all of its posts.
                        </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                        <AlertDialogCancel>Cancel</AlertDialogCancel>
                        <AlertDialogAction
                            onClick={handleDelete}
                            className="bg-destructive hover:bg-destructive/90"
                        >
                            Delete
                        </AlertDialogAction>
                    </AlertDialogFooter>
                </AlertDialogContent>
            </AlertDialog>
        </div>
    )
}
